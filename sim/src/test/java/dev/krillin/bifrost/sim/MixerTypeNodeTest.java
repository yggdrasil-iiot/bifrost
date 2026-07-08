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
 * TDD browse-read test: verifies MixerType (an OPC-UA ObjectType, ns=2;s=MixerType) exposes its
 * member variables (Rpm, Temp, Running, Secret) via HasComponent, with correct DataTypes, and
 * that the numeric members (Rpm, Temp) additionally expose an EURange property (via HasProperty)
 * with the expected engineering range. This mirrors exactly the browse/read wiring a future
 * Mímir client would rely on to derive a canonical definition from the type node alone.
 */
class MixerTypeNodeTest {

    private static final UInteger NODECLASS_ALL = Unsigned.uint(0xFF);
    private static final UInteger RESULT_ALL = Unsigned.uint(0x3F);

    @Test
    void browseMixerTypeMembersAndRanges() throws Exception {
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim().start()) {
            OpcUaClient client = OpcUaClient.create("opc.tcp://localhost:" + EmbeddedMiloSim.BIND_PORT);
            client.connect();
            try {
                NodeId mixerType = NodeId.parse("ns=2;s=MixerType");

                BrowseResult membersResult = client.browse(new BrowseDescription(
                        mixerType, BrowseDirection.Forward, Identifiers.HasComponent, false,
                        NODECLASS_ALL, RESULT_ALL));
                ReferenceDescription[] memberRefs = safeRefs(membersResult);

                Set<String> memberNames = new LinkedHashSet<>();
                for (ReferenceDescription ref : memberRefs) {
                    memberNames.add(ref.getBrowseName().getName());
                }
                assertEquals(Set.of("Rpm", "Temp", "Running", "Secret"), memberNames);

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
                        case "Rpm", "Temp", "Secret" -> assertEquals(11, dataTypeId, name + " should be Double");
                        case "Running" -> assertEquals(1, dataTypeId, name + " should be Boolean");
                        default -> throw new AssertionError("unexpected member: " + name);
                    }

                    if (name.equals("Rpm") || name.equals("Temp")) {
                        NodeId euRangeId = findEuRangeNodeId(client, memberId);
                        DataValue euDv = client.readValue(0.0, TimestampsToReturn.Neither, euRangeId);
                        ExtensionObject eo = (ExtensionObject) euDv.getValue().getValue();
                        Range range = (Range) eo.decode(client.getStaticEncodingContext());

                        if (name.equals("Rpm")) {
                            assertEquals(0.0, range.getLow());
                            assertEquals(3000.0, range.getHigh());
                        } else {
                            assertEquals(0.0, range.getLow());
                            assertEquals(450.0, range.getHigh());
                        }
                    }
                }
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void readMixerInstanceValues() throws Exception {
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim().start()) {
            OpcUaClient client = OpcUaClient.create("opc.tcp://localhost:" + EmbeddedMiloSim.BIND_PORT);
            client.connect();
            try {
                assertEquals(1535.0, readValue(client, "ns=2;s=Line1/Mixer1.Rpm"));
                assertEquals(200.0, readValue(client, "ns=2;s=Line1/Mixer1.Temp"));
                assertEquals(Boolean.TRUE, readValue(client, "ns=2;s=Line1/Mixer1.Running"));
                assertEquals(42.0, readValue(client, "ns=2;s=Line1/Mixer1.Secret"));

                BrowseResult membersResult = client.browse(new BrowseDescription(
                        NodeId.parse("ns=2;s=Line1/Mixer1"), BrowseDirection.Forward,
                        Identifiers.HasComponent, false, NODECLASS_ALL, RESULT_ALL));
                Set<String> memberNames = new LinkedHashSet<>();
                for (ReferenceDescription ref : safeRefs(membersResult)) {
                    memberNames.add(ref.getBrowseName().getName());
                }
                assertEquals(Set.of("Rpm", "Temp", "Running", "Secret"), memberNames);
            } finally {
                client.disconnect();
            }
        }
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
