package dev.krillin.bifrost.heimdall;

import java.util.List;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;

/**
 * Milo 1.0.0 OPC-UA client implementation of {@link Applier} — the write leg the lab lacked.
 *
 * <p>The Milo 1.0.0 Java client's read/write/connect are <b>synchronous</b> and throw the
 * checked {@link UaException} — there is no singular {@code writeValue} and no
 * {@code CompletableFuture.get(...)}: writes go through the batch {@code writeValues(List,List)}.
 *
 * <ul>
 *   <li>{@link #write}: write a Double {@link Variant}, then confirm by numeric read-back equality.</li>
 *   <li>{@link #call}: Boolean-trigger rising edge (write {@code true}, then poll the done node for a
 *       confirmed false→true transition). Never {@code ok} on "accepted" alone; a stale done=true is
 *       rejected as "no rising edge".</li>
 * </ul>
 */
public final class OpcUaApplier implements Applier {

    private final String endpoint;
    private OpcUaClient client;

    public OpcUaApplier(String endpoint) {
        this.endpoint = endpoint;
    }

    /** Connect a SecurityPolicy.None, anonymous client (synchronous 1.0.0 API). */
    public OpcUaApplier connect() throws UaException {
        client = OpcUaClient.create(endpoint);
        client.connect();
        return this;
    }

    @Override
    public ReadBack read(String nodeId) throws UaException {
        DataValue dv = client.readValue(0.0, TimestampsToReturn.Neither, NodeId.parse(nodeId));
        Object v = dv.getValue() != null ? dv.getValue().getValue() : null;
        boolean good = dv.getStatusCode() != null && dv.getStatusCode().isGood();
        return new ReadBack(v != null ? v.toString() : null, good);
    }

    @Override
    public double readDouble(String nodeId) throws UaException {
        // Reuse the existing stringified read and parse — fail-closed on bad/uncertain quality or a
        // null/non-numeric value. ② trusts this live antecedent read as authoritative, so a stale value
        // carried by a bad StatusCode must be rejected (mirrors write's read-back good() guard), not trusted.
        ReadBack rb = read(nodeId);
        if (!rb.good()) {
            throw new UaException(StatusCode.BAD, "readDouble from " + nodeId + " returned bad status");
        }
        if (rb.value() == null) {
            throw new UaException(StatusCode.BAD, "readDouble from " + nodeId + " returned null value");
        }
        try {
            return Double.parseDouble(rb.value().trim());
        } catch (NumberFormatException e) {
            throw new UaException(StatusCode.BAD, "readDouble from " + nodeId + " non-numeric: " + rb.value());
        }
    }

    @Override
    public Result write(String nodeId, double value) throws UaException {
        StatusCode sc = client.writeValues(
                List.of(NodeId.parse(nodeId)),
                List.of(new DataValue(new Variant(value)))).get(0);
        if (!sc.isGood()) {
            return new Result(false, "write to " + nodeId + " failed: " + sc);
        }
        ReadBack rb = read(nodeId);
        if (!rb.good()) {
            return new Result(false, "read-back from " + nodeId + " returned bad status");
        }
        boolean match = numericallyEqual(value, rb.value());
        return new Result(match, match
                ? "written+confirmed " + value + " to " + nodeId + " (read-back: " + rb.value() + ")"
                : "read-back mismatch on " + nodeId + ": wrote " + value + ", got " + rb.value());
    }

    @Override
    public Result call(String triggerNodeId, String doneNodeId, long timeoutMs) throws UaException {
        // Capture the baseline FIRST: a rising-edge confirm requires observing a false→true transition,
        // not merely "done is true now". A stale done=true (un-reset prior run) must NOT count.
        ReadBack baseline = read(doneNodeId);
        if (isTrue(baseline.value())) {
            return new Result(false,
                    "doneNode " + doneNodeId + " already true before call - reset required (no rising edge)");
        }

        StatusCode trigger = client.writeValues(
                List.of(NodeId.parse(triggerNodeId)),
                List.of(new DataValue(new Variant(Boolean.TRUE)))).get(0);
        if (!trigger.isGood()) {
            return new Result(false, "trigger write to " + triggerNodeId + " failed: " + trigger);
        }

        // Poll for the rising edge; swallow transient read errors — the deadline governs give-up.
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            try {
                if (isTrue(read(doneNodeId).value())) {
                    // Complete the handshake: release our own trigger output so the equipment rearms
                    // `done` for the next activate. Best-effort — the activation is already confirmed;
                    // a failed de-assert only annotates detail and is surfaced by the next call's
                    // baseline guard. We write only the trigger (our output), never the equipment's
                    // done bit (often read-only): apply the command value, then release the trigger.
                    String note;
                    try {
                        StatusCode dc = client.writeValues(
                                List.of(NodeId.parse(triggerNodeId)),
                                List.of(new DataValue(new Variant(Boolean.FALSE)))).get(0);
                        note = dc.isGood() ? "" : " (warning: trigger de-assert not confirmed: " + dc + ")";
                    } catch (Exception e) {
                        // Catch broadly: a de-assert must NEVER fail an already-confirmed activation,
                        // including on an unchecked throwable.
                        note = " (warning: trigger de-assert failed: " + e.getMessage() + ")";
                    }
                    return new Result(true, "rising-edge confirmed on " + doneNodeId + note);
                }
            } catch (UaException transientRead) {
                // keep polling until deadline
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        return new Result(false, "timeout (" + timeoutMs + "ms) waiting for rising edge on " + doneNodeId);
    }

    public void close() {
        if (client != null) {
            try {
                client.disconnect();
            } catch (Exception ignore) {
                // best-effort
            }
        }
    }

    private static boolean isTrue(String v) {
        return v != null && v.equalsIgnoreCase("true");
    }

    /** Numeric equality tolerant of "1500" vs "1500.0"; falls back to false if read-back is non-numeric. */
    private static boolean numericallyEqual(double written, String readBack) {
        if (readBack == null) {
            return false;
        }
        try {
            return Math.abs(written - Double.parseDouble(readBack)) < 1e-9;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
