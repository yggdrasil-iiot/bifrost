package yggdrasil.bifrost.heimdall;

import java.util.List;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned;

/**
 * Gate support: writes the sim's fault-injection node {@code Sim/<member>.StatusCode} (a UInt32), so
 * a gate can make a member report a Bad sample on demand. The control node models the sensor, not a
 * governed setpoint, so it is writable on the anonymous {@code None} endpoint even when the sim
 * requires an identity for the setpoints and the Method.
 *
 * <pre>
 *   java -cp bifrost-heimdall.jar ...SimStatusWriter "ns=2;s=Sim/Line1/Mixer1.Temp.StatusCode" 2150891520
 *   # [SIMSTATUS] WRITE ns=2;s=Sim/Line1/Mixer1.Temp.StatusCode = 2150891520 status=good
 * </pre>
 */
public final class SimStatusWriter {

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("usage: SimStatusWriter <nodeId> <uint32 status code>");
            System.exit(2);
        }
        String endpoint = System.getenv().getOrDefault("OPCUA_URL", "opc.tcp://localhost:48400");
        OpcUaClient client = OpcUaClient.create(
                endpoint,
                endpoints -> endpoints.stream()
                        .filter(e -> SecurityPolicy.None.getUri().equals(e.getSecurityPolicyUri()))
                        .findFirst(),
                transport -> { },
                cfg -> { });
        client.connect();
        try {
            StatusCode wrote = client.writeValues(
                    List.of(NodeId.parse(args[0])),
                    List.of(new DataValue(new Variant(Unsigned.uint(Long.parseLong(args[1])))))).get(0);
            System.out.println("[SIMSTATUS] WRITE " + args[0] + " = " + args[1]
                    + " status=" + (wrote.isGood() ? "good" : "0x" + Long.toHexString(wrote.getValue())));
            if (!wrote.isGood()) {
                System.exit(1);
            }
        } finally {
            client.disconnect();
        }
    }

    private SimStatusWriter() {
    }
}
