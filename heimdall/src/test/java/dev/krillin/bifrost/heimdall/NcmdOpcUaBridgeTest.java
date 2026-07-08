package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.Date;
import java.util.List;

import org.eclipse.tahu.message.model.Metric.MetricBuilder;
import org.eclipse.tahu.message.model.MetricDataType;
import org.eclipse.tahu.message.model.PropertyDataType;
import org.eclipse.tahu.message.model.PropertySet;
import org.eclipse.tahu.message.model.PropertySet.PropertySetBuilder;
import org.eclipse.tahu.message.model.PropertyValue;
import org.eclipse.tahu.message.model.SparkplugBPayload;
import org.eclipse.tahu.message.model.SparkplugBPayload.SparkplugBPayloadBuilder;
import org.junit.jupiter.api.Test;

import dev.krillin.bifrost.core.acl.AclMapperFactory;
import dev.krillin.bifrost.core.acl.CommandPolicy;
import dev.krillin.bifrost.core.acl.Constraint;
import dev.krillin.bifrost.core.acl.Rule;
import dev.krillin.bifrost.core.acl.Target;
import dev.krillin.bifrost.core.conformance.ConformancePolicy;
import dev.krillin.bifrost.core.conformance.CrossConstraint;
import dev.krillin.bifrost.core.conformance.NodeBinding;
import dev.krillin.bifrost.core.schema.Member;
import dev.krillin.bifrost.core.schema.Range;
import dev.krillin.bifrost.core.schema.SemVer;
import dev.krillin.bifrost.core.schema.UdtDefinition;

/**
 * The bridge core: decode ONE authorizable command metric, authorize deny-by-default at the edge,
 * apply through the injected {@link Applier}, and produce a correlated {@link NcmdResponse}.
 * No broker or OPC-UA server is involved — a {@link FakeApplier} records interactions.
 */
class NcmdOpcUaBridgeTest {

    private static final String GROUP = "Bifrost:Line1";
    private static final String EDGE = "recipe-edge";
    private static final String NCMD_TOPIC = "spBv1.0/" + GROUP + "/NCMD/" + EDGE;
    private static final String QUERY_TOPIC = "bifrost/" + GROUP + "/QUERY/" + EDGE;

    private CommandPolicy policy() throws Exception {
        return AclMapperFactory.create()
                .readValue(Path.of("registry/policy.json").toFile(), CommandPolicy.class);
    }

    private NcmdOpcUaBridge bridge(Applier applier) throws Exception {
        return new NcmdOpcUaBridge(GROUP, EDGE, policy(), applier, null, null, null);
    }

    /** Build a single-command-metric NCMD payload per the bridge's wire contract. */
    private static SparkplugBPayload cmd(String cmdId, String op, String name, Object value,
                                         MetricDataType dt, String doneNode, Long timeoutMs) throws Exception {
        PropertySetBuilder pb = new PropertySetBuilder()
                .addProperty("op", new PropertyValue(PropertyDataType.String, op));
        if (doneNode != null) pb.addProperty("doneNode", new PropertyValue(PropertyDataType.String, doneNode));
        if (timeoutMs != null) pb.addProperty("timeoutMs", new PropertyValue(PropertyDataType.Int64, timeoutMs));
        PropertySet props = pb.createPropertySet();
        return new SparkplugBPayloadBuilder()
                .setUuid(cmdId)
                .setTimestamp(new Date())
                .addMetric(new MetricBuilder(name, dt, value).properties(props).createMetric())
                .createPayload();
    }

    @Test void allowed_write_is_applied_and_confirmed() throws Exception {
        FakeApplier fake = new FakeApplier();
        NcmdResponse r = bridge(fake).handle(NCMD_TOPIC,
                cmd("c-1", "write", "ns=2;s=Recipe/Rpm", 1500.0, MetricDataType.Double, null, null));
        assertTrue(fake.writeCalled, "applier.write must be called for an allowed write");
        assertEquals("ns=2;s=Recipe/Rpm", fake.lastWriteNode);
        assertEquals(1500.0, fake.lastWriteValue);
        assertTrue(r.ok());
        assertEquals("c-1", r.cmdId());
    }

    @Test void denied_above_max_is_not_applied() throws Exception {
        FakeApplier fake = new FakeApplier();
        NcmdResponse r = bridge(fake).handle(NCMD_TOPIC,
                cmd("c-2", "write", "ns=2;s=Recipe/Rpm", 9999.0, MetricDataType.Double, null, null));
        assertFalse(fake.writeCalled, "an above-max write must NOT reach the applier");
        assertFalse(r.ok());
        assertTrue(r.detail().contains("denied"), r.detail());
    }

    @Test void deny_by_default_node_is_not_applied() throws Exception {
        FakeApplier fake = new FakeApplier();
        NcmdResponse r = bridge(fake).handle(NCMD_TOPIC,
                cmd("c-3", "write", "ns=2;s=Recipe/Secret", 1.0, MetricDataType.Double, null, null));
        assertFalse(fake.writeCalled);
        assertFalse(r.ok());
        assertTrue(r.detail().contains("denied"), r.detail());
    }

    @Test void read_query_bypasses_authorization() throws Exception {
        FakeApplier fake = new FakeApplier();
        fake.readResult = new Applier.ReadBack("1500.0", true);
        NcmdResponse r = bridge(fake).handle(QUERY_TOPIC,
                cmd("c-4", "read", "ns=2;s=Recipe/Rpm", null, MetricDataType.String, null, null));
        assertTrue(fake.readCalled, "a QUERY/read must call applier.read");
        assertFalse(fake.writeCalled);
        assertEquals("1500.0", r.value());
        assertTrue(r.good());
        assertTrue(r.ok());
        assertEquals("c-4", r.cmdId());
    }

    @Test void allowed_call_applies_with_donenode_and_timeout() throws Exception {
        FakeApplier fake = new FakeApplier();
        NcmdResponse r = bridge(fake).handle(NCMD_TOPIC,
                cmd("c-5", "call", "ns=2;s=Recipe/ApplyRecipe", Boolean.TRUE, MetricDataType.Boolean,
                        "ns=2;s=Recipe/ApplyDone", 30000L));
        assertTrue(fake.callCalled, "an allowed trigger must call applier.call");
        assertEquals("ns=2;s=Recipe/ApplyRecipe", fake.lastCallTrigger);
        assertEquals("ns=2;s=Recipe/ApplyDone", fake.lastCallDone);
        assertEquals(30000L, fake.lastCallTimeout);
        assertTrue(r.ok());
    }

    // ----- ② conformance: cross-member + envelope from the governed model (after ① authz) -----

    private static final String WELD_NODE = "ns=2;s=Weld/WeldCurrent";
    private static final String FORCE_READ_NODE = "ns=2;s=BodyShop/Weld1.ElectrodeForce";

    /** ACL that AUTHORIZES the Weld setpoint generously (max 100) so ② conformance — not ① authz — is the gate. */
    private CommandPolicy weldAclPolicy() {
        Rule r = new Rule("weld", "recipe-writer", new Target(GROUP, EDGE, null),
                WELD_NODE, new Constraint("Double", 0.0, 100.0));
        return new CommandPolicy("1.0.0", List.of(r), "deny");
    }

    /** Governed equipment model: WeldCurrent[0,12], WeldTime[0,500], ElectrodeForce[0,6]. */
    private UdtDefinition weldDef() {
        return new UdtDefinition("Weld-Controller", SemVer.parse("1.0.0"),
                List.of(new Member("WeldCurrent", "Double", null, new Range(0, 12)),
                        new Member("WeldTime", "Double", null, new Range(0, 500)),
                        new Member("ElectrodeForce", "Double", null, new Range(0, 6))),
                List.of(), null);
    }

    /** Envelope-mode policy with the weld-lobe cross-constraint (ElectrodeForce lt 3.0 ⇒ WeldCurrent le 8.0). */
    private ConformancePolicy weldPolicy() {
        return new ConformancePolicy("weld-lobe-policy", "1.0.0", "Weld-Controller", "1.0.0",
                new ConformancePolicy.Dial("envelope", null, null, null),
                List.of(new CrossConstraint("weld-lobe", "ElectrodeForce", "lt", 3.0, "WeldCurrent", "le", 8.0)),
                List.of(new NodeBinding(WELD_NODE, null, "WeldCurrent"),
                        new NodeBinding(null, FORCE_READ_NODE, "ElectrodeForce")));
    }

    private NcmdOpcUaBridge weldBridge(Applier applier) {
        return new NcmdOpcUaBridge(GROUP, EDGE, weldAclPolicy(), applier, weldDef(), weldPolicy(), null);
    }

    @Test void conformance_cross_member_violation_is_denied_and_not_applied() throws Exception {
        // ElectrodeForce read = 2.5 (< 3.0) ⇒ require WeldCurrent le 8.0; 9 violates the weld-lobe.
        FakeApplier fake = new FakeApplier();
        fake.readDoubleResult = 2.5;
        NcmdResponse r = weldBridge(fake).handle(NCMD_TOPIC,
                cmd("w-1", "write", WELD_NODE, 9.0, MetricDataType.Double, null, null));
        assertFalse(fake.writeCalled, "a cross-member-violating write must NOT reach the applier");
        assertFalse(r.ok());
        assertTrue(r.detail().contains("conformance.cross.weld-lobe"), r.detail());
        assertEquals(FORCE_READ_NODE, fake.lastReadDoubleNode, "the bound ElectrodeForce sibling must be read");
    }

    @Test void conformant_write_is_applied() throws Exception {
        // ElectrodeForce read = 2.5 (< 3.0) ⇒ require WeldCurrent le 8.0; 7 satisfies it and is in envelope.
        FakeApplier fake = new FakeApplier();
        fake.readDoubleResult = 2.5;
        NcmdResponse r = weldBridge(fake).handle(NCMD_TOPIC,
                cmd("w-2", "write", WELD_NODE, 7.0, MetricDataType.Double, null, null));
        assertTrue(fake.writeCalled, "a conformant write must reach the applier");
        assertEquals(WELD_NODE, fake.lastWriteNode);
        assertEquals(7.0, fake.lastWriteValue);
        assertTrue(r.ok());
    }

    @Test void bad_quality_sibling_read_is_denied_fail_closed() throws Exception {
        // The antecedent (ElectrodeForce) live read fails/bad-quality => ② fail-closed => DENY, never applied.
        FakeApplier fake = new FakeApplier();
        fake.throwOnReadDoubleNode = FORCE_READ_NODE;   // Fix 1: bad-quality read must not be trusted
        NcmdResponse r = weldBridge(fake).handle(NCMD_TOPIC,
                cmd("w-4", "write", WELD_NODE, 7.0, MetricDataType.Double, null, null));
        assertFalse(fake.writeCalled, "a write must NOT apply when the antecedent read failed");
        assertFalse(r.ok());
        assertTrue(r.detail().contains("conformance-error"), r.detail());
    }

    /** Policy whose ElectrodeForce binding has readNodeId=null — the antecedent can't be resolved. */
    private ConformancePolicy weldPolicyUnresolvableSibling() {
        return new ConformancePolicy("weld-lobe-policy", "1.0.0", "Weld-Controller", "1.0.0",
                new ConformancePolicy.Dial("envelope", null, null, null),
                List.of(new CrossConstraint("weld-lobe", "ElectrodeForce", "lt", 3.0, "WeldCurrent", "le", 8.0)),
                List.of(new NodeBinding(WELD_NODE, null, "WeldCurrent"),
                        new NodeBinding(null, null, "ElectrodeForce")));   // no readNodeId => unresolvable
    }

    @Test void unresolvable_antecedent_binding_is_denied_fail_closed() throws Exception {
        // Fix 2: a needed cross-member with no numeric readNodeId cannot be verified => fail-closed DENY.
        FakeApplier fake = new FakeApplier();
        fake.readDoubleResult = 2.5;
        NcmdOpcUaBridge bridge = new NcmdOpcUaBridge(GROUP, EDGE, weldAclPolicy(), fake,
                weldDef(), weldPolicyUnresolvableSibling(), null);
        NcmdResponse r = bridge.handle(NCMD_TOPIC,
                cmd("w-5", "write", WELD_NODE, 7.0, MetricDataType.Double, null, null));
        assertFalse(fake.writeCalled, "a write must NOT apply when a needed antecedent binding is unresolvable");
        assertFalse(r.ok());
        assertTrue(r.detail().contains("conformance-error"), r.detail());
    }

    @Test void above_envelope_max_is_denied_by_conformance() throws Exception {
        // Authz allows 13 (max 100), but the governed envelope caps WeldCurrent at 12 ⇒ spec.range.above-max.
        FakeApplier fake = new FakeApplier();
        fake.readDoubleResult = 2.5;
        NcmdResponse r = weldBridge(fake).handle(NCMD_TOPIC,
                cmd("w-3", "write", WELD_NODE, 13.0, MetricDataType.Double, null, null));
        assertFalse(fake.writeCalled, "an above-envelope write must NOT reach the applier");
        assertFalse(r.ok());
        assertTrue(r.detail().contains("above-max"), r.detail());
    }

    /** Records interactions and returns programmed results. */
    static final class FakeApplier implements Applier {
        boolean writeCalled, callCalled, readCalled;
        String lastWriteNode;
        double lastWriteValue;
        String lastCallTrigger, lastCallDone;
        long lastCallTimeout;
        String lastReadDoubleNode;
        double readDoubleResult = 0.0;
        String throwOnReadDoubleNode;   // if set, readDouble(node) throws (simulates a bad-quality/failed read)
        Result writeResult = new Result(true, "written+confirmed");
        Result callResult = new Result(true, "rising-edge confirmed");
        ReadBack readResult = new ReadBack("1500.0", true);

        @Override public ReadBack read(String nodeId) {
            readCalled = true;
            return readResult;
        }
        @Override public double readDouble(String nodeId) throws Exception {
            lastReadDoubleNode = nodeId;
            if (nodeId.equals(throwOnReadDoubleNode)) {
                throw new Exception("readDouble bad quality " + nodeId);
            }
            return readDoubleResult;
        }
        @Override public Result write(String nodeId, double value) {
            writeCalled = true;
            lastWriteNode = nodeId;
            lastWriteValue = value;
            return writeResult;
        }
        @Override public Result call(String triggerNodeId, String doneNodeId, long timeoutMs) {
            callCalled = true;
            lastCallTrigger = triggerNodeId;
            lastCallDone = doneNodeId;
            lastCallTimeout = timeoutMs;
            return callResult;
        }
    }
}
