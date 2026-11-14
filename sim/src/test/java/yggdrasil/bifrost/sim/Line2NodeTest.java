package yggdrasil.bifrost.sim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned;
import org.eclipse.milo.opcua.stack.core.types.enumerated.BrowseDirection;
import org.eclipse.milo.opcua.stack.core.types.enumerated.NodeClass;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.BrowseDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.ReadValueId;
import org.eclipse.milo.opcua.stack.core.types.structured.ReferenceDescription;
import org.junit.jupiter.api.Test;

/**
 * Line2 as a client sees it: a FolderType {@code Line2} under Objects organizing three
 * {@code StationType} instances, and two {@code ToolType} nutrunners organized (not composed) under
 * Station1. All 22 members are client-read-only, start at their neutral defaults with Good status,
 * and form one initial snapshot with one shared source timestamp.
 */
class Line2NodeTest {

    static final String NS = "ns=2;s=";

    static final List<String> STATIONS = List.of("Line2/Station1", "Line2/Station2", "Line2/Station3");
    static final List<String> TOOLS = List.of("Line2/Station1/Nutrunner1", "Line2/Station1/Nutrunner2");
    static final List<String> STATION_MEMBERS = List.of("Running", "UnitId", "VisitId", "VisitPresent");
    static final List<String> TOOL_MEMBERS = List.of("Torque", "Running", "UnitId", "VisitId", "VisitPresent");

    /** The 13 identifiers the forseti fixtures name. */
    static final List<String> FIXTURE_IDS = List.of(
            "Line2/Station1.Running", "Line2/Station2.Running", "Line2/Station3.Running",
            "Line2/Station1.UnitId", "Line2/Station1.VisitId", "Line2/Station1.VisitPresent",
            "Line2/Station1/Nutrunner1.Torque", "Line2/Station1/Nutrunner1.Running",
            "Line2/Station1/Nutrunner1.UnitId", "Line2/Station1/Nutrunner1.VisitId",
            "Line2/Station1/Nutrunner1.VisitPresent",
            "Line2/Station1/Nutrunner2.Torque", "Line2/Station1/Nutrunner2.Running");

    /** All 22 members in the scan's fixed order: stations, then each tool's five members. */
    static List<String> allMembers() {
        List<String> ids = new ArrayList<>();
        for (String s : STATIONS) {
            for (String m : STATION_MEMBERS) {
                ids.add(s + "." + m);
            }
        }
        for (String t : TOOLS) {
            for (String m : TOOL_MEMBERS) {
                ids.add(t + "." + m);
            }
        }
        return ids;
    }

    static NodeId dataTypeOf(String memberId) {
        String m = memberId.substring(memberId.lastIndexOf('.') + 1);
        return switch (m) {
            case "Running", "VisitPresent" -> NodeIds.Boolean;
            case "UnitId", "VisitId" -> NodeIds.String;
            case "Torque" -> NodeIds.Double;
            default -> throw new IllegalArgumentException(memberId);
        };
    }

    static Object defaultOf(String memberId) {
        NodeId t = dataTypeOf(memberId);
        return t.equals(NodeIds.Boolean) ? Boolean.FALSE : t.equals(NodeIds.String) ? "" : (Object) 0.0;
    }

    /** A sim whose scheduled scan never fires during a test, so only the test drives a scan. */
    static EmbeddedMiloSim quietSim() {
        return new EmbeddedMiloSim(EmbeddedMiloSim.BIND_PORT, EmbeddedMiloSim.DEFAULT_BIND_HOST, false, null,
                EmbeddedMiloSim.MAX_SCAN_MS);
    }

    @Test
    void allMembersExistWithTheirDataTypeAndAreClientReadOnly() throws Exception {
        assertEquals(22, allMembers().size());
        assertTrue(allMembers().containsAll(FIXTURE_IDS));
        try (EmbeddedMiloSim sim = quietSim().start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                for (String id : allMembers()) {
                    NodeId n = NodeId.parse(NS + id);
                    assertEquals(dataTypeOf(id), attr(client, n, AttributeId.DataType), id);
                    assertEquals(Unsigned.ubyte(1), attr(client, n, AttributeId.AccessLevel), id);
                    assertEquals(Unsigned.ubyte(1), attr(client, n, AttributeId.UserAccessLevel), id);
                    assertEquals(NodeClass.Variable.getValue(),
                            ((Number) attr(client, n, AttributeId.NodeClass)).intValue(), id);
                }
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void membersStartAtNeutralDefaultsWithGoodStatusInOneSnapshot() throws Exception {
        try (EmbeddedMiloSim sim = quietSim().start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                List<DataValue> values = readAll(client, allMembers());
                Set<Long> sourceTimes = new HashSet<>();
                for (int i = 0; i < values.size(); i++) {
                    String id = allMembers().get(i);
                    DataValue dv = values.get(i);
                    assertEquals(defaultOf(id), dv.getValue().getValue(), id);
                    assertTrue(dv.getStatusCode().isGood(), id);
                    assertNotNull(dv.getSourceTime(), id);
                    sourceTimes.add(dv.getSourceTime().getUtcTime());
                    // A Read reports its own ServerTimestamp (see storedValue), so the stored
                    // DataValue is where the sim's server time = source time is visible.
                    DataValue stored = storedValue(sim, id);
                    assertEquals(stored.getSourceTime(), stored.getServerTime(), id + " server time = source time");
                    assertEquals(dv.getSourceTime(), stored.getSourceTime(), id);
                }
                assertEquals(1, sourceTimes.size(), "one initial snapshot, one source timestamp");
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void stationTypeAndToolTypeAreConcreteSubtypesOfBaseObjectType() throws Exception {
        try (EmbeddedMiloSim sim = quietSim().start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                Set<String> subtypes = new HashSet<>();
                for (ReferenceDescription r : browse(client, NodeIds.BaseObjectType, BrowseDirection.Forward,
                        NodeIds.HasSubtype)) {
                    subtypes.add(r.getNodeId().toParseableString());
                }
                for (String type : List.of("StationType", "ToolType")) {
                    NodeId t = NodeId.parse(NS + type);
                    assertTrue(subtypes.contains(t.expanded().toParseableString()), type + " under BaseObjectType");
                    assertEquals(Boolean.FALSE, attr(client, t, AttributeId.IsAbstract), type);
                    assertEquals(NodeClass.ObjectType.getValue(),
                            ((Number) attr(client, t, AttributeId.NodeClass)).intValue(), type);
                    assertEquals(type, ((QualifiedName)
                            attr(client, t, AttributeId.BrowseName)).getName());
                }
                assertEquals(STATION_MEMBERS, componentNames(client, NodeId.parse(NS + "StationType")));
                assertEquals(TOOL_MEMBERS, componentNames(client, NodeId.parse(NS + "ToolType")));
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void instancesHaveExactlyTheirTypesMembersAndTheToolsHangUnderStation1ByOrganizes() throws Exception {
        try (EmbeddedMiloSim sim = quietSim().start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                NodeId line2 = NodeId.parse(NS + "Line2");
                assertEquals(NodeIds.FolderType, typeDefinition(client, line2));
                assertEquals("Line2", ((QualifiedName)
                        attr(client, line2, AttributeId.BrowseName)).getName());
                assertEquals(new HashSet<>(STATIONS), targets(client, line2, NodeIds.Organizes));

                for (String s : STATIONS) {
                    NodeId station = NodeId.parse(NS + s);
                    assertEquals(NodeId.parse(NS + "StationType"), typeDefinition(client, station), s);
                    assertEquals(STATION_MEMBERS, componentNames(client, station), s);
                    assertEquals(s.substring(s.lastIndexOf('/') + 1),
                            ((QualifiedName)
                                    attr(client, station, AttributeId.BrowseName)).getName());
                }

                NodeId station1 = NodeId.parse(NS + "Line2/Station1");
                assertEquals(new HashSet<>(TOOLS), targets(client, station1, NodeIds.Organizes));
                Set<String> components = targets(client, station1, NodeIds.HasComponent);
                for (String t : TOOLS) {
                    assertFalse(components.contains(t), t + " is organized, not a component");
                }
                for (String s : List.of("Line2/Station2", "Line2/Station3")) {
                    assertTrue(targets(client, NodeId.parse(NS + s), NodeIds.Organizes).isEmpty(), s);
                }

                for (String t : TOOLS) {
                    NodeId tool = NodeId.parse(NS + t);
                    assertEquals(NodeId.parse(NS + "ToolType"), typeDefinition(client, tool), t);
                    assertEquals(TOOL_MEMBERS, componentNames(client, tool), t);
                    assertEquals(t.substring(t.lastIndexOf('/') + 1),
                            ((QualifiedName)
                                    attr(client, tool, AttributeId.BrowseName)).getName());
                }
            } finally {
                client.disconnect();
            }
        }
    }

    /** Line2 is the only child the Objects folder gained over the baseline. */
    @Test
    void line2IsTheOnlyNewChildOfObjects() throws Exception {
        Set<String> baseline = baselineObjectsChildren();
        try (EmbeddedMiloSim sim = quietSim().start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                var table = client.getNamespaceTable();
                Set<String> added = new HashSet<>();
                for (ReferenceDescription r : browse(client, NodeIds.ObjectsFolder, BrowseDirection.Forward,
                        NodeIds.HierarchicalReferences)) {
                    String id = LegacySimCompatibilityTest.nodeId(r.getNodeId().toNodeId(table).orElseThrow(), table);
                    if (!baseline.remove(id)) {
                        added.add(id);
                    }
                }
                assertTrue(baseline.isEmpty(), "baseline children still present: " + baseline);
                assertEquals(Set.of("nsu=urn:bifrost:opcua:sim;String=Line2"), added);
            } finally {
                client.disconnect();
            }
        }
    }

    // ----- helpers -----

    /**
     * The DataValue the sim last set on a Line2 member, exactly as set. Read from the node's field
     * because Milo 1.1.8's {@code UaVariableNode.getAttribute(Value)} - and so every Read and every
     * sample - returns a copy whose ServerTimestamp is replaced with the time of that read. The
     * source timestamp passes through unchanged; the stored server timestamp is visible only here.
     */
    static DataValue storedValue(EmbeddedMiloSim sim, String id) throws Exception {
        Object node = sim.namespace().getNodeManager().getNode(NodeId.parse(NS + id)).orElseThrow();
        java.lang.reflect.Field f = org.eclipse.milo.opcua.sdk.server.nodes.UaVariableNode.class
                .getDeclaredField("value");
        f.setAccessible(true);
        return (DataValue) f.get(node);
    }

    static Set<String> baselineObjectsChildren() throws Exception {
        String json;
        try (InputStream in = Line2NodeTest.class.getResourceAsStream(LegacySimCompatibilityTest.BASELINE)) {
            assertNotNull(in);
            json = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        String section = json.substring(json.indexOf("\"objectsChildren\""), json.indexOf("\"nodes\""));
        Set<String> ids = new HashSet<>();
        Matcher m = Pattern.compile("\"(nsu=[^ ]+) ").matcher(section);
        while (m.find()) {
            ids.add(m.group(1));
        }
        assertFalse(ids.isEmpty());
        return ids;
    }

    static Object attr(OpcUaClient client, NodeId node, AttributeId attribute) throws Exception {
        DataValue dv = client.read(0.0, TimestampsToReturn.Neither,
                List.of(new ReadValueId(node, attribute.uid(), null, null))).getResults()[0];
        assertTrue(dv.getStatusCode().isGood(), node + " " + attribute + " = " + dv.getStatusCode());
        return dv.getValue().getValue();
    }

    static List<DataValue> readAll(OpcUaClient client, List<String> ids) throws Exception {
        List<ReadValueId> reads = new ArrayList<>();
        for (String id : ids) {
            reads.add(new ReadValueId(NodeId.parse(NS + id), AttributeId.Value.uid(), null, null));
        }
        return List.of(client.read(0.0, TimestampsToReturn.Both, reads).getResults());
    }

    static ReferenceDescription[] browse(OpcUaClient client, NodeId node, BrowseDirection direction,
                                         NodeId referenceType) throws Exception {
        ReferenceDescription[] refs = client.browse(new BrowseDescription(node, direction, referenceType,
                true, Unsigned.uint(0xFF), Unsigned.uint(0x3F))).getReferences();
        return refs == null ? new ReferenceDescription[0] : refs;
    }

    /** Browse names of the forward HasComponent Variables, in browse order. */
    static List<String> componentNames(OpcUaClient client, NodeId node) throws Exception {
        List<String> names = new ArrayList<>();
        for (ReferenceDescription r : browse(client, node, BrowseDirection.Forward, NodeIds.HasComponent)) {
            assertEquals(NodeClass.Variable, r.getNodeClass(), node + " component " + r.getBrowseName());
            names.add(r.getBrowseName().getName());
        }
        return names;
    }

    /** String identifiers of the forward targets of exactly this reference type (no subtypes). */
    static Set<String> targets(OpcUaClient client, NodeId node, NodeId referenceType) throws Exception {
        Set<String> ids = new HashSet<>();
        for (ReferenceDescription r : client.browse(new BrowseDescription(node, BrowseDirection.Forward,
                referenceType, false, Unsigned.uint(0xFF), Unsigned.uint(0x3F))).getReferences()) {
            ids.add(r.getNodeId().getIdentifier().toString());
        }
        return ids;
    }

    static NodeId typeDefinition(OpcUaClient client, NodeId node) throws Exception {
        Map<String, NodeId> defs = new LinkedHashMap<>();
        for (ReferenceDescription r : browse(client, node, BrowseDirection.Forward, NodeIds.HasTypeDefinition)) {
            defs.put(r.getNodeId().toParseableString(), r.getNodeId().toNodeId(client.getNamespaceTable()).orElseThrow());
        }
        assertEquals(1, defs.size(), node + " has one type definition");
        return defs.values().iterator().next();
    }
}
