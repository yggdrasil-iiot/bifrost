package dev.krillin.bifrost.heimdall;

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

    /** Read outcome: the stringified value + whether the OPC-UA StatusCode was Good. */
    record ReadBack(String value, boolean good) {}

    /** Apply outcome: whether the write/call was confirmed, plus a human-readable detail. */
    record Result(boolean ok, String detail) {}
}
