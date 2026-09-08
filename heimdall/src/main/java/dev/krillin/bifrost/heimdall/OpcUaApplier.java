package dev.krillin.bifrost.heimdall;

import java.util.List;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.identity.X509IdentityProvider;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;

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
 *
 * <p><b>The session re-establishes itself.</b> The client used to be built once at startup and never
 * rebuilt, so a single OPC-UA server restart turned every subsequent command into a fail-closed
 * DENY until a human restarted the bridge. Now a transport fault marks the session dead and the
 * next command reconnects, behind a backoff so a down server is not hammered once per command.
 */
public final class OpcUaApplier implements Applier {

    /** How long to wait before retrying a failed connect. Bounds the cost of a down server. */
    private static final long BACKOFF_MS = 5_000L;

    private final String endpoint;

    /** Nullable: tests construct the applier without one. */
    private final EdgeHealth health;

    /**
     * Written by {@link #ensureConnected()} under this object's lock and read by every apply
     * stripe, so it must be volatile. Before the striped executor existed this field was written
     * exactly once, at startup, and plain access was safe.
     */
    private volatile OpcUaClient client;
    private volatile boolean connected;
    private volatile long nextRetryAt;

    /**
     * The edge's OPC-UA identity, or null for the anonymous {@code SecurityPolicy.None} path.
     *
     * <p>Null is the default and every gate written before R3 runs that way, which is what keeps
     * those gates meaningful: this round adds a capability, it does not change the posture.
     */
    private final EdgeIdentity identity;

    public OpcUaApplier(String endpoint) {
        this(endpoint, null, null);
    }

    public OpcUaApplier(String endpoint, EdgeHealth health) {
        this(endpoint, health, null);
    }

    public OpcUaApplier(String endpoint, EdgeHealth health, EdgeIdentity identity) {
        this.endpoint = endpoint;
        this.health = health;
        this.identity = identity;
    }

    /** Connect — anonymous on SecurityPolicy.None, or with the edge's certificate if one is set. */
    public OpcUaApplier connect() throws Exception {
        ensureConnected();
        return this;
    }

    /**
     * Is this status a transport/session fault rather than a verdict about a value? Only the former
     * means "the plant is not visible"; classifying {@code Bad_OutOfRange} as a connection fault
     * would hide a real refusal behind a retry.
     *
     * <p>{@code Bad_Timeout} is included as a judgement call: a server slow enough to time out is
     * one the edge cannot confirm a write against, and the backoff bounds the cost of being wrong.
     * If a site sees healthy-but-slow servers flapping into plant-unreachable, this is the line to
     * revisit.
     */
    static boolean isConnectionFault(StatusCode sc) {
        if (sc == null) {
            return false;
        }
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
     * Is this endpoint one the edge may present its identity on?
     *
     * <p>The failure this guards is a <b>silent downgrade</b>. If an anonymous {@code None}
     * endpoint were acceptable, an edge configured with an identity would connect happily without
     * presenting it, and row 12's whole claim would be lost behind a green log line. So the answer
     * is yes only for {@code Basic256Sha256} with {@code SignAndEncrypt}: signing alone leaves the
     * command values on the wire in clear, which is not what this round claims to establish.
     */
    static boolean isSecure(String securityPolicyUri, MessageSecurityMode mode) {
        return SecurityPolicy.Basic256Sha256.getUri().equals(securityPolicyUri)
                && MessageSecurityMode.SignAndEncrypt.equals(mode);
    }

    static boolean isSecure(EndpointDescription e) {
        return e != null && isSecure(e.getSecurityPolicyUri(), e.getSecurityMode());
    }

    /**
     * Did this throwable come from the transport failing, rather than from the server rendering a
     * verdict about a value?
     *
     * <p>{@link #isConnectionFault(StatusCode)} alone is not enough, which the resilience gate
     * proved: when the server dies mid-session, Milo attempts its own reconnect and the failure
     * arrives as a Netty {@code AnnotatedConnectException} ("Connection refused") wrapped in the
     * thrown exception — carrying no OPC-UA StatusCode at all. That was being reported to the
     * operator as {@code apply error: io.netty.channel...}, which is the same defect as reporting
     * it as a conformance error: a transport failure dressed up as something about the command.
     *
     * <p>Every Netty/JDK connect and reset failure is an {@link java.io.IOException} somewhere in
     * the cause chain, and a value-level refusal never is, so the chain is the honest test.
     */
    private static boolean hasTransportCause(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof java.io.IOException) {
                return true;
            }
            if (c.getCause() == c) {
                break;   // defensive: never loop on a self-referencing cause
            }
        }
        return false;
    }

    /** True when a failure out of a Milo call means "the plant is not visible". */
    private static boolean isUnreachable(Exception e) {
        if (e instanceof UaException ua && isConnectionFault(ua.getStatusCode())) {
            return true;
        }
        return hasTransportCause(e);
    }

    /**
     * Ensure a usable session, or say the plant is unreachable.
     *
     * <p>{@code synchronized} because the apply path is striped: without it two stripes can both
     * enter, both call {@code OpcUaClient.create(...).connect()}, and one client leaks while other
     * threads observe a half-published reference. The backoff guard is the second point — a dead
     * server must not be hammered once per command, and a command arriving inside the window is
     * answered immediately rather than made to wait out a connect timeout.
     */
    private synchronized void ensureConnected() throws PlantUnreachableException {
        if (connected && client != null) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now < nextRetryAt) {
            throw new PlantUnreachableException(
                    "OPC-UA disconnected; next retry in " + (nextRetryAt - now) + "ms");
        }
        try {
            if (client != null) {
                try {
                    client.disconnect();
                } catch (Exception ignore) {
                    // best-effort: we are replacing it regardless
                }
            }
            client = identity == null ? createAnonymous() : createGoverned();
            client.connect();
            connected = true;
            if (health != null) {
                health.plantReachable();
            }
            System.out.println("[BRIDGE] OPC-UA session re-established to " + endpoint);
        } catch (Exception e) {
            connected = false;
            nextRetryAt = now + BACKOFF_MS;
            throw new PlantUnreachableException(
                    "OPC-UA connect to " + endpoint + " failed: " + e.getMessage(), e);
        }
    }

    /** The pre-R3 path, unchanged: anonymous, {@code SecurityPolicy.None}. */
    private OpcUaClient createAnonymous() throws UaException {
        return OpcUaClient.create(endpoint);
    }

    /**
     * Connect presenting the edge's certificate, on a {@code Basic256Sha256}/{@code SignAndEncrypt}
     * endpoint, with an X.509 user identity token.
     *
     * <p>The endpoint selector is deliberately strict and the empty case is turned into a message
     * that names the cause. Milo's own failure for "no endpoint matched" is opaque, and the reading
     * an operator would take from it — that the server is down — is precisely wrong: the server is
     * up and is not offering a secured endpoint. An edge that quietly fell back to the anonymous
     * endpoint instead would defeat the entire round.
     */
    private OpcUaClient createGoverned() throws Exception {
        try {
            return OpcUaClient.create(
                    endpoint,
                    endpoints -> endpoints.stream().filter(OpcUaApplier::isSecure).findFirst(),
                    transport -> { },
                    cfg -> cfg
                            .setApplicationUri(identity.applicationUri())
                            .setCertificate(identity.certificate())
                            .setKeyPair(identity.keyPair())
                            .setIdentityProvider(new X509IdentityProvider(
                                    identity.certificate(), identity.keyPair().getPrivate())));
        } catch (Exception e) {
            // Decided behaviour, not a fallback. When no secure endpoint is offered, the edge
            // REFUSES rather than quietly using the anonymous one: an edge holding an identity and
            // not presenting it is the exact defect this round exists to remove, and it would look
            // green in every log. Milo's own message for "no endpoint matched" is opaque and reads
            // like the server is down, when in fact the server is up and offering nothing secure.
            throw new PlantUnreachableException(
                    "no Basic256Sha256/SignAndEncrypt endpoint at " + endpoint
                            + "; an identity is configured so the anonymous endpoint is deliberately"
                            + " not used (" + e.getMessage() + ")", e);
        }
    }

    /** Mark the session dead so the next command reconnects instead of inheriting a dead client. */
    private synchronized PlantUnreachableException fault(String what, Throwable cause) {
        connected = false;
        nextRetryAt = System.currentTimeMillis() + BACKOFF_MS;
        if (health != null) {
            health.plantUnreachable();
        }
        return new PlantUnreachableException(what, cause);
    }

    @Override
    public ReadBack read(String nodeId) throws Exception {
        ensureConnected();
        DataValue dv;
        try {
            dv = client.readValue(0.0, TimestampsToReturn.Neither, NodeId.parse(nodeId));
        } catch (Exception e) {
            if (isUnreachable(e)) {
                throw fault("read " + nodeId + ": " + e.getMessage(), e);
            }
            throw e;
        }
        if (isConnectionFault(dv.getStatusCode())) {
            throw fault("read " + nodeId + ": " + dv.getStatusCode(), null);
        }
        Object v = dv.getValue() != null ? dv.getValue().getValue() : null;
        boolean good = dv.getStatusCode() != null && dv.getStatusCode().isGood();
        return new ReadBack(v != null ? v.toString() : null, good);
    }

    @Override
    public double readDouble(String nodeId) throws Exception {
        // Reuse the existing stringified read and parse — fail-closed on bad/uncertain quality or a
        // null/non-numeric value. ② trusts this live antecedent read as authoritative, so a stale value
        // carried by a bad StatusCode must be rejected (mirrors write's read-back good() guard), not trusted.
        // A PlantUnreachableException from read() propagates: not being able to see the node is a
        // different event from the node answering badly, and only the latter is a conformance verdict.
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
    public Result write(String nodeId, double value) throws Exception {
        ensureConnected();
        StatusCode sc;
        try {
            sc = client.writeValues(
                    List.of(NodeId.parse(nodeId)),
                    List.of(new DataValue(new Variant(value)))).get(0);
        } catch (Exception e) {
            if (isUnreachable(e)) {
                throw fault("write " + nodeId + ": " + e.getMessage(), e);
            }
            throw e;
        }
        if (isConnectionFault(sc)) {
            throw fault("write " + nodeId + ": " + sc, null);
        }
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
    public Result call(String triggerNodeId, String doneNodeId, long timeoutMs) throws Exception {
        ensureConnected();
        // Capture the baseline FIRST: a rising-edge confirm requires observing a false→true transition,
        // not merely "done is true now". A stale done=true (un-reset prior run) must NOT count.
        ReadBack baseline = read(doneNodeId);
        if (isTrue(baseline.value())) {
            return new Result(false,
                    "doneNode " + doneNodeId + " already true before call - reset required (no rising edge)");
        }

        StatusCode trigger;
        try {
            trigger = client.writeValues(
                    List.of(NodeId.parse(triggerNodeId)),
                    List.of(new DataValue(new Variant(Boolean.TRUE)))).get(0);
        } catch (Exception e) {
            if (isUnreachable(e)) {
                throw fault("trigger write " + triggerNodeId + ": " + e.getMessage(), e);
            }
            throw e;
        }
        if (isConnectionFault(trigger)) {
            throw fault("trigger write " + triggerNodeId + ": " + trigger, null);
        }
        if (!trigger.isGood()) {
            return new Result(false, "trigger write to " + triggerNodeId + " failed: " + trigger);
        }

        // Poll for the rising edge; swallow transient read errors — the deadline governs give-up.
        // A PlantUnreachableException is NOT swallowed here: it is not a UaException, so it
        // propagates out of this method. A closed session is not a transient read, and burning the
        // full timeout against a server that is gone would report a timeout instead of an outage.
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
                        // including on an unchecked throwable or a lost session.
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
        OpcUaClient c = client;
        if (c != null) {
            try {
                c.disconnect();
            } catch (Exception ignore) {
                // best-effort
            }
        }
        connected = false;
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
