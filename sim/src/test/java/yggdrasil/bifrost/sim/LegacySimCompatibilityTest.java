package yggdrasil.bifrost.sim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.core.Reference;
import org.eclipse.milo.opcua.sdk.server.nodes.UaNode;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.NamespaceTable;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExpandedNodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExtensionObject;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned;
import org.eclipse.milo.opcua.stack.core.types.enumerated.BrowseDirection;
import org.eclipse.milo.opcua.stack.core.types.enumerated.NodeClass;
import org.eclipse.milo.opcua.stack.core.types.structured.Argument;
import org.eclipse.milo.opcua.stack.core.types.structured.BrowseDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.ReferenceDescription;
import org.junit.jupiter.api.Test;

/**
 * Every node the sim served before Line2 existed is still served exactly as it was.
 *
 * <p>The baseline {@code legacy-address-space.json} was dumped from the unmodified sim at
 * {@code 4d79b87}: for every node in the sim namespace its NodeId, node class, browse and display
 * name, the class's attributes (DataType, ValueRank, access levels, IsAbstract, Executable, ...),
 * its type definition, its sorted references, and its initial value and StatusCode. Namespace
 * indexes are written as URIs, so the dump does not depend on index assignment; timestamps are left
 * out, because the scan re-stamps them. The dump is taken server-side because the {@code Sim/}
 * control nodes have no references at all and cannot be reached by browsing.
 *
 * <p>Nodes added later (the Line2 folder, its instances, their types and their {@code Sim/Line2/}
 * controls) are excluded by identifier before comparing, so the comparison is: the current address
 * space minus the new nodes equals the baseline, node for node and attribute for attribute. The
 * children of the Objects folder are compared the same way, so {@code Line2} is the only child that
 * may be added there.
 *
 * <p>To regenerate (only ever from an unmodified baseline commit):
 * {@code mvn -pl sim test -Dtest=LegacySimCompatibilityTest -Dbifrost.sim.writeBaseline=<path>}.
 */
class LegacySimCompatibilityTest {

    static final String BASELINE = "/legacy-address-space.json";

    @Test
    void theLegacyAddressSpaceIsUnchanged() throws Exception {
        String current;
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim().start()) {
            current = dump(sim);
        }
        String out = System.getProperty("bifrost.sim.writeBaseline");
        if (out != null && !out.isBlank()) {
            Files.writeString(Path.of(out), current, StandardCharsets.UTF_8);
            return;
        }
        String baseline;
        try (InputStream in = LegacySimCompatibilityTest.class.getResourceAsStream(BASELINE)) {
            assertNotNull(in, "baseline resource " + BASELINE);
            // The working tree may check the resource out with CRLF; the content is compared as LF.
            baseline = new String(in.readAllBytes(), StandardCharsets.UTF_8).replace("\r\n", "\n");
        }
        assertEquals(baseline, current);
    }

    /** True for a node that Line2 added; everything else must match the baseline. */
    static boolean isLine2Addition(String identifier) {
        return identifier.equals("Line2") || identifier.startsWith("Line2/")
                || identifier.startsWith("Sim/Line2/")
                || identifier.equals("StationType") || identifier.startsWith("StationType.")
                || identifier.equals("ToolType") || identifier.startsWith("ToolType.");
    }

    static String dump(EmbeddedMiloSim sim) throws Exception {
        EmbeddedMiloSim.SimNamespace ns = namespaceOf(sim);
        NamespaceTable table = ns.getNodeContext().getServer().getNamespaceTable();

        Map<String, String> nodes = new TreeMap<>();
        for (UaNode node : ns.getNodeManager().getNodes()) {
            String id = node.getNodeId().getIdentifier().toString();
            if (isLine2Addition(id)) {
                continue;
            }
            nodes.put(nodeId(node.getNodeId(), table), node(node, table));
        }

        List<String> objects = new ArrayList<>();
        OpcUaClient client = SimStatusControlTest.connect();
        try {
            ReferenceDescription[] refs = client.browse(new BrowseDescription(
                    NodeIds.ObjectsFolder, BrowseDirection.Forward, NodeIds.HierarchicalReferences,
                    true, Unsigned.uint(0xFF), Unsigned.uint(0x3F))).getReferences();
            for (ReferenceDescription r : refs) {
                NodeId target = r.getNodeId().toNodeId(table).orElseThrow();
                if (target.getNamespaceIndex().intValue() != 0
                        && isLine2Addition(target.getIdentifier().toString())) {
                    continue;
                }
                objects.add(nodeId(target, table) + " " + qualifiedName(r.getBrowseName(), table)
                        + " via " + nodeId(r.getReferenceTypeId(), table));
            }
        } finally {
            client.disconnect();
        }
        objects.sort(Comparator.naturalOrder());

        StringBuilder sb = new StringBuilder();
        sb.append("{\n  \"objectsChildren\": [\n");
        for (int i = 0; i < objects.size(); i++) {
            sb.append("    ").append(str(objects.get(i))).append(i + 1 < objects.size() ? ",\n" : "\n");
        }
        sb.append("  ],\n  \"nodes\": [\n");
        int i = 0;
        for (String body : nodes.values()) {
            sb.append(body).append(++i < nodes.size() ? ",\n" : "\n");
        }
        sb.append("  ]\n}\n");
        return sb.toString();
    }

    private static String node(UaNode node, NamespaceTable table) {
        Map<String, String> f = new java.util.LinkedHashMap<>();
        f.put("nodeId", nodeId(node.getNodeId(), table));
        f.put("nodeClass", node.getNodeClass().name());
        f.put("browseName", qualifiedName(node.getBrowseName(), table));
        f.put("displayName", value(node.getDisplayName(), table));
        f.put("description", value(node.getAttribute(AttributeId.Description), table));
        f.put("writeMask", value(node.getAttribute(AttributeId.WriteMask), table));
        f.put("userWriteMask", value(node.getAttribute(AttributeId.UserWriteMask), table));
        for (AttributeId a : classAttributes(node.getNodeClass())) {
            f.put(lowerFirst(a.name()), value(node.getAttribute(a), table));
        }
        if (node.getNodeClass() == NodeClass.Variable) {
            DataValue dv = (DataValue) node.getAttribute(AttributeId.Value);
            f.put("value", value(dv.getValue().getValue(), table));
            f.put("status", String.format("0x%08X", dv.getStatusCode().getValue()));
        }
        String typeDefinition = null;
        List<String> refs = new ArrayList<>();
        for (Reference r : node.getReferences()) {
            String target = expanded(r.getTargetNodeId(), table);
            if (r.isForward() && r.getReferenceTypeId().equals(NodeIds.HasTypeDefinition)) {
                typeDefinition = target;
            }
            refs.add((r.isForward() ? "-> " : "<- ") + nodeId(r.getReferenceTypeId(), table) + " " + target);
        }
        refs.sort(Comparator.naturalOrder());
        f.put("typeDefinition", typeDefinition);

        StringBuilder sb = new StringBuilder("    {\n");
        for (Map.Entry<String, String> e : f.entrySet()) {
            sb.append("      ").append(str(e.getKey())).append(": ").append(str(e.getValue())).append(",\n");
        }
        sb.append("      \"references\": [");
        for (int i = 0; i < refs.size(); i++) {
            sb.append(i == 0 ? "\n" : ",\n").append("        ").append(str(refs.get(i)));
        }
        sb.append(refs.isEmpty() ? "]\n" : "\n      ]\n").append("    }");
        return sb.toString();
    }

    private static List<AttributeId> classAttributes(NodeClass nodeClass) {
        return switch (nodeClass) {
            case Variable -> List.of(AttributeId.DataType, AttributeId.ValueRank, AttributeId.ArrayDimensions,
                    AttributeId.AccessLevel, AttributeId.UserAccessLevel,
                    AttributeId.MinimumSamplingInterval, AttributeId.Historizing);
            case Object -> List.of(AttributeId.EventNotifier);
            case ObjectType, VariableType, DataType, ReferenceType -> List.of(AttributeId.IsAbstract);
            case Method -> List.of(AttributeId.Executable, AttributeId.UserExecutable);
            default -> List.of();
        };
    }

    private static String lowerFirst(String s) {
        return Character.toLowerCase(s.charAt(0)) + s.substring(1);
    }

    static String nodeId(NodeId id, NamespaceTable table) {
        return "nsu=" + table.get(id.getNamespaceIndex()) + ";" + id.getType().name() + "=" + id.getIdentifier();
    }

    private static String expanded(ExpandedNodeId id, NamespaceTable table) {
        return id.toNodeId(table).map(n -> nodeId(n, table)).orElse("unresolved " + id);
    }

    private static String qualifiedName(QualifiedName q, NamespaceTable table) {
        return table.get(q.getNamespaceIndex()) + "|" + q.getName();
    }

    /** A type-tagged, deterministic rendering of an attribute value. */
    private static String value(Object o, NamespaceTable table) {
        if (o == null) {
            return null;
        }
        if (o.getClass().isArray()) {
            StringBuilder sb = new StringBuilder(o.getClass().getComponentType().getSimpleName()).append("[");
            for (int i = 0; i < Array.getLength(o); i++) {
                sb.append(i == 0 ? "" : ", ").append(value(Array.get(o, i), table));
            }
            return sb.append("]").toString();
        }
        if (o instanceof NodeId n) {
            return "NodeId " + nodeId(n, table);
        }
        if (o instanceof ExpandedNodeId n) {
            return "ExpandedNodeId " + expanded(n, table);
        }
        if (o instanceof QualifiedName q) {
            return "QualifiedName " + qualifiedName(q, table);
        }
        if (o instanceof LocalizedText t) {
            return "LocalizedText " + t.getLocale() + "|" + t.getText();
        }
        if (o instanceof ExtensionObject x) {
            Object body = x.getBody();
            String rendered = body instanceof ByteString b ? hex(b.bytesOrEmpty()) : String.valueOf(body);
            return "ExtensionObject " + nodeId(x.getEncodingOrTypeId(), table) + " " + rendered;
        }
        if (o instanceof Argument a) {
            return "Argument name=" + a.getName() + " dataType=" + value(a.getDataType(), table)
                    + " valueRank=" + a.getValueRank() + " arrayDimensions=" + value(a.getArrayDimensions(), table)
                    + " description=" + value(a.getDescription(), table);
        }
        if (o instanceof ByteString b) {
            return "ByteString " + hex(b.bytesOrEmpty());
        }
        return o.getClass().getSimpleName() + " " + o;
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static String str(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20 || c > 0x7e) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }

    /** The sim's namespace, read reflectively so this test runs against the unmodified sim too. */
    static EmbeddedMiloSim.SimNamespace namespaceOf(EmbeddedMiloSim sim) throws Exception {
        Field f = EmbeddedMiloSim.class.getDeclaredField("namespace");
        f.setAccessible(true);
        return (EmbeddedMiloSim.SimNamespace) f.get(sim);
    }
}
