package dev.krillin.bifrost.sim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExtensionObject;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned;
import org.eclipse.milo.opcua.stack.core.types.enumerated.BrowseDirection;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.BrowseDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.BrowseResult;
import org.eclipse.milo.opcua.stack.core.types.structured.ReadValueId;
import org.eclipse.milo.opcua.stack.core.types.structured.Range;
import org.eclipse.milo.opcua.stack.core.types.structured.ReferenceDescription;
import org.junit.jupiter.api.Test;

/**
 * TDD browse-read test: verifies WeldControllerType (an OPC-UA ObjectType, ns=2;s=WeldControllerType)
 * exposes its member variables (WeldCurrent, WeldTime, ElectrodeForce) via HasComponent, with correct
 * DataTypes, and that each member exposes an EURange property (via HasProperty) with the expected
 * engineering range. Also verifies the BodyShop/Weld1 instance seeds and the Weld/WeldCurrent
 * setpoint -> instance transfer. Mirrors {@link MixerTypeNodeTest}.
 */
class WeldControllerNodeTest {

    private static final UInteger NODECLASS_ALL = Unsigned.uint(0xFF);
    private static final UInteger RESULT_ALL = Unsigned.uint(0x3F);

    @Test
    void browseWeldControllerTypeMembersAndRanges() throws Exception {
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim().start()) {
            OpcUaClient client = OpcUaClient.create("opc.tcp://localhost:" + EmbeddedMiloSim.BIND_PORT);
            client.connect();
            try {
                NodeId weldType = NodeId.parse("ns=2;s=WeldControllerType");

                BrowseResult membersResult = client.browse(new BrowseDescription(
                        weldType, BrowseDirection.Forward, Identifiers.HasComponent, false,
                        NODECLASS_ALL, RESULT_ALL));
                ReferenceDescription[] memberRefs = safeRefs(membersResult);

                Set<String> memberNames = new LinkedHashSet<>();
                for (ReferenceDescription ref : memberRefs) {
                    memberNames.add(ref.getBrowseName().getName());
                }
                assertEquals(Set.of("WeldCurrent", "WeldTime", "ElectrodeForce"), memberNames);

                for (ReferenceDescription ref : memberRefs) {
                    String name = ref.getBrowseName().getName();
                    NodeId memberId = ref.getNodeId().toNodeId(client.getNamespaceTable()).orElseThrow();

                    DataValue dataTypeDv = readAttribute(client, memberId, AttributeId.DataType);
                    Object dataTypeVal = dataTypeDv.getValue().getValue();
                    assertTrue(dataTypeVal instanceof NodeId, "DataType attribute should be a NodeId for " + name);
                    NodeId dataTypeNode = (NodeId) dataTypeVal;
                    assertTrue(dataTypeNode.getIdentifier() instanceof UInteger,
                            "DataType NodeId identifier should be numeric for " + name);
                    int dataTypeId = ((UInteger) dataTypeNode.getIdentifier()).intValue();

                    switch (name) {
                        case "WeldCurrent", "WeldTime", "ElectrodeForce" ->
                                assertEquals(11, dataTypeId, name + " should be Double");
                        default -> throw new AssertionError("unexpected member: " + name);
                    }

                    NodeId euRangeId = findEuRangeNodeId(client, memberId);
                    DataValue euDv = client.readValue(0.0, TimestampsToReturn.Neither, euRangeId);
                    ExtensionObject eo = (ExtensionObject) euDv.getValue().getValue();
                    Range range = (Range) eo.decode(client.getStaticEncodingContext());

                    switch (name) {
                        case "WeldCurrent" -> {
                            assertEquals(0.0, range.getLow());
                            assertEquals(12.0, range.getHigh());
                        }
                        case "WeldTime" -> {
                            assertEquals(0.0, range.getLow());
                            assertEquals(500.0, range.getHigh());
                        }
                        case "ElectrodeForce" -> {
                            assertEquals(0.0, range.getLow());
                            assertEquals(6.0, range.getHigh());
                        }
                        default -> throw new AssertionError("unexpected member: " + name);
                    }
                }
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void readWeldInstanceValues() throws Exception {
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim().start()) {
            OpcUaClient client = OpcUaClient.create("opc.tcp://localhost:" + EmbeddedMiloSim.BIND_PORT);
            client.connect();
            try {
                assertEquals(6.0, readValue(client, "ns=2;s=BodyShop/Weld1.WeldCurrent"));
                assertEquals(200.0, readValue(client, "ns=2;s=BodyShop/Weld1.WeldTime"));
                assertEquals(2.5, readValue(client, "ns=2;s=BodyShop/Weld1.ElectrodeForce"));

                BrowseResult membersResult = client.browse(new BrowseDescription(
                        NodeId.parse("ns=2;s=BodyShop/Weld1"), BrowseDirection.Forward,
                        Identifiers.HasComponent, false, NODECLASS_ALL, RESULT_ALL));
                Set<String> memberNames = new LinkedHashSet<>();
                for (ReferenceDescription ref : safeRefs(membersResult)) {
                    memberNames.add(ref.getBrowseName().getName());
                }
                assertEquals(Set.of("WeldCurrent", "WeldTime", "ElectrodeForce"), memberNames);
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void writingWeldSetpointTransfersToInstance() throws Exception {
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim().start()) {
            OpcUaClient client = OpcUaClient.create("opc.tcp://localhost:" + EmbeddedMiloSim.BIND_PORT);
            client.connect();
            try {
                // Baseline: instance holds its seeded value before any setpoint write.
                assertEquals(6.0, readValue(client, "ns=2;s=BodyShop/Weld1.WeldCurrent"));

                // Write the southbound setpoint -> the sim transfers it to the instance.
                writeDouble(client, "ns=2;s=Weld/WeldCurrent", 9.0);
                assertEquals(9.0, readValue(client, "ns=2;s=BodyShop/Weld1.WeldCurrent"));

                // The other members are untouched by the WeldCurrent transfer.
                assertEquals(200.0, readValue(client, "ns=2;s=BodyShop/Weld1.WeldTime"));
                assertEquals(2.5, readValue(client, "ns=2;s=BodyShop/Weld1.ElectrodeForce"));
            } finally {
                client.disconnect();
            }
        }
    }

    private static void writeDouble(OpcUaClient client, String nodeId, double value) throws Exception {
        client.writeValues(List.of(NodeId.parse(nodeId)), List.of(new DataValue(new Variant(value))));
    }

    private static Object readValue(OpcUaClient client, String nodeId) throws Exception {
        DataValue dv = client.readValue(0.0, TimestampsToReturn.Neither, NodeId.parse(nodeId));
        return dv.getValue() != null ? dv.getValue().getValue() : null;
    }

    private static NodeId findEuRangeNodeId(OpcUaClient client, NodeId memberId) throws Exception {
        BrowseResult propsResult = client.browse(new BrowseDescription(
                memberId, BrowseDirection.Forward, Identifiers.HasProperty, false,
                NODECLASS_ALL, RESULT_ALL));
        for (ReferenceDescription ref : safeRefs(propsResult)) {
            if ("EURange".equals(ref.getBrowseName().getName())) {
                return ref.getNodeId().toNodeId(client.getNamespaceTable()).orElseThrow();
            }
        }
        throw new AssertionError("no EURange property found via HasProperty on " + memberId);
    }

    private static DataValue readAttribute(OpcUaClient client, NodeId node, AttributeId attr) throws Exception {
        ReadValueId rvid = new ReadValueId(node, attr.uid(), null, QualifiedName.NULL_VALUE);
        var resp = client.read(0.0, TimestampsToReturn.Neither, List.of(rvid));
        DataValue[] results = resp.getResults();
        return (results != null && results.length > 0) ? results[0] : null;
    }

    private static ReferenceDescription[] safeRefs(BrowseResult res) {
        ReferenceDescription[] refs = res != null ? res.getReferences() : null;
        return refs != null ? refs : new ReferenceDescription[0];
    }
}
