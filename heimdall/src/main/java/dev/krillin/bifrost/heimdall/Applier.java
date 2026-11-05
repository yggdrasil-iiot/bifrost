package dev.krillin.bifrost.heimdall;

import java.util.function.Function;

/**
 * The physical apply seam the bridge drives after an edge-authorization ALLOW.
 * Implemented by {@link OpcUaApplier} (live Milo client) in production and by a fake in tests,
 * so the bridge core ({@link NcmdOpcUaBridge#handle}) is unit-testable with no live OPC-UA server.
 *
 * <p>Any method here may throw {@link PlantUnreachableException} to say the plant was not visible.
 * That is not a verdict: the bridge answers with a distinct reason code and retries the connection,
 * rather than reporting it as a policy or conformance refusal.
 */
public interface Applier {

    /** Read a node's current value (no authorization — reads are observation, not command). */
    ReadBack read(String nodeId) throws Exception;

    /**
     * Read a node's current value as a primitive {@code double} — used by the ② conformance check to
     * pull the live value of a bound numeric cross-member sibling. Throws if the node is unreadable or
     * its value is non-numeric (the bridge treats any such failure as fail-closed DENY).
     */
    double readDouble(String nodeId) throws Exception;

    /** Write a Double setpoint and confirm by numeric read-back equality. */
    Result write(String nodeId, double value) throws Exception;

    /**
     * Rising-edge Boolean trigger, complete one-shot handshake: write {@code true} to
     * {@code triggerNodeId}, poll {@code doneNodeId} for a confirmed false→true transition within
     * {@code timeoutMs}, then release the trigger (write {@code false}) so the equipment rearms
     * {@code done} for the next activate. Never {@code ok} on "accepted" alone; a stale done=true
     * is rejected as "no rising edge". The release is best-effort — a failed release does not fail
     * an already-confirmed activation (it is surfaced by the next call's baseline guard).
     */
    Result call(String triggerNodeId, String doneNodeId, long timeoutMs) throws Exception;

    /**
     * Read a node with its source timestamp, for the Method path's live precondition. A default so
     * the write/call fakes need not implement a path they never drive.
     */
    default Sample sample(String nodeId) throws Exception {
        throw new UnsupportedOperationException("sample");
    }

    /**
     * Call an OPC UA Method with one Double input, after {@code endpoint} returned null for the calling client's
     * {@link Peer} (otherwise {@link EndpointRefused}, and no call). {@code ok} only when the call's StatusCode and
     * every input argument's result are Good; {@code output} is the first output argument.
     */
    default MethodResult method(String objectNodeId, String methodNodeId, double input, Function<Peer, String> endpoint)
            throws Exception {
        throw new UnsupportedOperationException("method");
    }

    /**
     * The server the current session authenticated: the server certificate it presented (DER) and the ApplicationUri of
     * the endpoint description the session was created on. Opens the session if there is none.
     */
    default Peer peer() throws Exception {
        throw new UnsupportedOperationException("peer");
    }

    /** An authenticated server: its certificate (DER, null if none) and its endpoint description's ApplicationUri. */
    record Peer(byte[] certificate, String applicationUri) {}

    /**
     * The client about to make a Method call is not on the linked server: {@code endpoint} returned this reason for its
     * {@link Peer}, so the call was not made. A {@code method} implementation asks {@code endpoint} on the same client it
     * then calls with, so a reconnect between the bridge's first comparison and the call cannot slip another server in.
     */
    final class EndpointRefused extends Exception {
        public EndpointRefused(String reason) {
            super(reason);
        }
    }

    /** A sample: its value, whether its StatusCode was Good, and its source timestamp (null if absent). */
    record Sample(Object value, boolean good, java.time.Instant sourceTime) {}

    /** A Method call's outcome. */
    record MethodResult(boolean ok, String output, String detail) {}

    /** Read outcome: the stringified value + whether the OPC-UA StatusCode was Good. */
    record ReadBack(String value, boolean good) {}

    /** Apply outcome: whether the write/call was confirmed, plus a human-readable detail. */
    record Result(boolean ok, String detail) {}
}
