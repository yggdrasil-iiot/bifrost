package yggdrasil.bifrost.sim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned;
import org.eclipse.milo.opcua.stack.core.types.enumerated.BrowseDirection;
import org.eclipse.milo.opcua.stack.core.types.enumerated.NodeClass;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.BrowseDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.ReferenceDescription;
import org.junit.jupiter.api.Test;

/**
 * The sim can serve a governed member with a non-Good StatusCode. Writing a raw 32-bit code to
 * {@code ns=2;s=Sim/Line1/Mixer1.Temp.StatusCode} re-sets {@code Line1/Mixer1.Temp} with that code and
 * fresh source and server timestamps; the value itself is untouched. The control nodes are not
 * components of Mixer1, so a client browsing the instance (Muninn) still sees exactly its four members.
 * A scan re-stamps a steady value every {@code SCAN_MS}, keeping its StatusCode.
 */
class SimStatusControlTest {

    static final String TEMP = "ns=2;s=Line1/Mixer1.Temp";
    static final String TEMP_STATUS = "ns=2;s=Sim/Line1/Mixer1.Temp.StatusCode";
    static final long BAD_SENSOR_FAILURE = 0x808B0000L;
    static final long UNCERTAIN_LAST_USABLE = 0x40900000L;

    @Test
    void defaultIsGood() throws Exception {
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim().start()) {
            OpcUaClient client = connect();
            try {
                assertTrue(read(client, TEMP).getStatusCode().isGood());
                assertEquals(Unsigned.uint(0), read(client, TEMP_STATUS).getValue().getValue());
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void writtenStatusReachesTheMemberWithFreshTimestamps() throws Exception {
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim().start()) {
            OpcUaClient client = connect();
            try {
                long before = DateTime.now().getJavaTime();
                write(client, TEMP_STATUS, BAD_SENSOR_FAILURE);
                DataValue bad = read(client, TEMP);
                assertEquals(BAD_SENSOR_FAILURE, bad.getStatusCode().getValue());
                assertEquals(200.0, bad.getValue().getValue());
                assertTrue(bad.getSourceTime().getJavaTime() >= before, "source timestamp is fresh");
                assertTrue(bad.getServerTime().getJavaTime() >= before, "server timestamp is fresh");

                write(client, TEMP_STATUS, UNCERTAIN_LAST_USABLE);
                assertEquals(UNCERTAIN_LAST_USABLE, read(client, TEMP).getStatusCode().getValue());

                write(client, TEMP_STATUS, 0);
                DataValue good = read(client, TEMP);
                assertTrue(good.getStatusCode().isGood());
                assertEquals(200.0, good.getValue().getValue());
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void setpointTransferKeepsTheForcedStatus() throws Exception {
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim().start()) {
            OpcUaClient client = connect();
            try {
                write(client, TEMP_STATUS, BAD_SENSOR_FAILURE);
                StatusCode written = client.writeValues(List.of(NodeId.parse("ns=2;s=Recipe/Temp")),
                        List.of(new DataValue(new Variant(210.0)))).get(0);
                assertTrue(written.isGood());
                DataValue v = read(client, TEMP);
                assertEquals(210.0, v.getValue().getValue());
                assertEquals(BAD_SENSOR_FAILURE, v.getStatusCode().getValue());
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void scanRestampsASteadyValueAndKeepsItsStatus() throws Exception {
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim().start()) {
            OpcUaClient client = connect();
            try {
                write(client, TEMP_STATUS, BAD_SENSOR_FAILURE);
                long first = read(client, TEMP).getSourceTime().getJavaTime();
                long deadline = System.currentTimeMillis() + 3 * EmbeddedMiloSim.SimNamespace.SCAN_MS;
                DataValue later = read(client, TEMP);
                while (later.getSourceTime().getJavaTime() <= first && System.currentTimeMillis() < deadline) {
                    Thread.sleep(50);
                    later = read(client, TEMP);
                }
                assertTrue(later.getSourceTime().getJavaTime() > first, "a scan re-stamped the member");
                assertEquals(200.0, later.getValue().getValue());
                assertEquals(BAD_SENSOR_FAILURE, later.getStatusCode().getValue());
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void controlNodesAreNotInstanceMembers() throws Exception {
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim().start()) {
            OpcUaClient client = connect();
            try {
                ReferenceDescription[] refs = client.browse(new BrowseDescription(
                        NodeId.parse("ns=2;s=Line1/Mixer1"), BrowseDirection.Forward, NodeIds.HierarchicalReferences,
                        true, Unsigned.uint(0xFF), Unsigned.uint(0x3F))).getReferences();
                Set<String> names = new LinkedHashSet<>();
                for (ReferenceDescription r : refs) {
                    if (r.getNodeClass() == NodeClass.Variable) {
                        names.add(r.getBrowseName().getName());
                    }
                }
                assertEquals(Set.of("Rpm", "Temp", "Running", "Secret"), names);
                for (ReferenceDescription r : refs) {
                    assertFalse(r.getNodeId().getIdentifier().toString().startsWith("Sim/"));
                }
            } finally {
                client.disconnect();
            }
        }
    }

    static OpcUaClient connect() throws Exception {
        OpcUaClient client = OpcUaClient.create("opc.tcp://localhost:" + EmbeddedMiloSim.BIND_PORT);
        client.connect();
        return client;
    }

    static DataValue read(OpcUaClient client, String nodeId) throws Exception {
        return client.readValue(0.0, TimestampsToReturn.Both, NodeId.parse(nodeId));
    }

    static void write(OpcUaClient client, String nodeId, long code) throws Exception {
        StatusCode result = client.writeValues(List.of(NodeId.parse(nodeId)),
                List.of(new DataValue(new Variant(UInteger.valueOf(code))))).get(0);
        assertTrue(result.isGood(), "write " + nodeId + " = " + result);
    }
}
