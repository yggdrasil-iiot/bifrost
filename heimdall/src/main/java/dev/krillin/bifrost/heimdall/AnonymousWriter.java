package dev.krillin.bifrost.heimdall;

import java.util.List;
import java.util.Optional;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;

/**
 * Gate support: the <b>second client</b> that {@code docs/ENTERPRISE.md} row 12 is about. Connects
 * anonymously to the {@code SecurityPolicy.None} endpoint and, in ONE process against ONE session,
 * reads the node and then writes it — printing both outcomes with the symbolic status name.
 *
 * <p>One session for both matters. The read is what proves this client was genuinely connected and
 * talking to the server; run it in a separate process from the write and that proof is decoupled
 * from the refusal it is meant to qualify — "the write failed" would then also be satisfied by a
 * client that never connected at all.
 *
 * <pre>
 *   java -cp bifrost-heimdall.jar …AnonymousWriter &lt;nodeId&gt; &lt;double value&gt;
 *   # [ANON] READ  ns=2;s=Recipe/Rpm = 1500.0 status=Good
 *   # [ANON] WRITE ns=2;s=Recipe/Rpm = 4242.0 status=Bad_UserAccessDenied
 * </pre>
 */
public final class AnonymousWriter {

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("usage: AnonymousWriter <nodeId> <double value>");
            System.exit(2);
        }
        String endpoint = System.getenv().getOrDefault("OPCUA_URL", "opc.tcp://localhost:48400");
        String nodeId = args[0];
        double value = Double.parseDouble(args[1]);

        // Select the None endpoint EXPLICITLY. The one-arg OpcUaClient.create(url) picks the
        // highest-security endpoint on offer, so once the server also offers Basic256Sha256 this
        // client would land there and fail with "no certificate chain configured" - which is not
        // the refusal the gate is trying to observe. This client's whole job is to be the
        // unprivileged second client, so it must sit where such a client actually sits.
        OpcUaClient client = OpcUaClient.create(
                endpoint,
                endpoints -> endpoints.stream()
                        .filter(e -> SecurityPolicy.None.getUri().equals(e.getSecurityPolicyUri()))
                        .findFirst(),
                transport -> { },
                cfg -> { });
        client.connect();
        try {
            DataValue read = client.readValue(0.0, TimestampsToReturn.Neither, NodeId.parse(nodeId));
            Object v = read.getValue() != null ? read.getValue().getValue() : null;
            System.out.println("[ANON] READ  " + nodeId + " = " + v
                    + " status=" + name(read.getStatusCode()));

            StatusCode wrote = client.writeValues(
                    List.of(NodeId.parse(nodeId)),
                    List.of(new DataValue(new Variant(value)))).get(0);
            System.out.println("[ANON] WRITE " + nodeId + " = " + value
                    + " status=" + name(wrote));
        } finally {
            try {
                client.disconnect();
            } catch (Exception ignore) {
                // best-effort
            }
        }
    }

    /**
     * The symbolic status name, so a gate can assert {@code Bad_UserAccessDenied} specifically.
     * Asserting merely "not good" would also be satisfied by {@code Bad_NodeIdUnknown} from a typo
     * in the node id, or by {@code Bad_TypeMismatch} — neither of which says anything about who is
     * allowed to write.
     */
    private static String name(StatusCode sc) {
        if (sc == null) {
            return "null";
        }
        Optional<String[]> looked = StatusCodes.lookup(sc.getValue());
        return looked.map(a -> a[0]).orElse(sc.isGood() ? "Good" : "0x" + Long.toHexString(sc.getValue()));
    }

    private AnonymousWriter() {
    }
}
