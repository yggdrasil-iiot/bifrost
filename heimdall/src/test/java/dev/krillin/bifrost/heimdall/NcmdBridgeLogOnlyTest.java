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
import dev.krillin.bifrost.core.conformance.ConformancePolicy;
import dev.krillin.bifrost.core.conformance.NodeBinding;
import dev.krillin.bifrost.core.schema.Member;
import dev.krillin.bifrost.core.schema.Range;
import dev.krillin.bifrost.core.schema.SemVer;
import dev.krillin.bifrost.core.schema.UdtDefinition;

/**
 * ENFORCEMENT_LOG_ONLY — the rollout mode from {@code docs/ADOPTION.md} phase 4. A command that
 * ①authz or ②conformance would refuse is logged and then APPLIED, so an edge can be introduced at a
 * running plant with no possibility of stopping the line on day one.
 *
 * <p>The tests that matter most here are the negative ones: log-only must not become a way for a
 * malformed payload to be silently reported as success, must not change anything about a command
 * that was allowed anyway, and must leave the enforcing default untouched.
 */
class NcmdBridgeLogOnlyTest {

    private static final String GROUP = "Bifrost:Line1";
    private static final String EDGE = "recipe-edge";
    private static final String NCMD_TOPIC = "spBv1.0/" + GROUP + "/NCMD/" + EDGE;
    private static final String QUERY_TOPIC = "bifrost/" + GROUP + "/QUERY/" + EDGE;

    /** Not in the deny-by-default edge policy — the shape of a command an unlisted device would send. */
    private static final String UNLISTED = "ns=2;s=Recipe/Secret";
    private static final String RPM = "ns=2;s=Recipe/Rpm";

    private CommandPolicy policy() throws Exception {
        return AclMapperFactory.create()
                .readValue(Path.of("registry/policy.json").toFile(), CommandPolicy.class);
    }

    private NcmdOpcUaBridge enforcing(Applier applier) throws Exception {
        return new NcmdOpcUaBridge(GROUP, EDGE, policy(), applier, null, null, null);
    }

    private NcmdOpcUaBridge logOnly(Applier applier) throws Exception {
        return new NcmdOpcUaBridge(GROUP, EDGE, policy(), applier, null, null, null, true);
    }

    private static SparkplugBPayload write(String cmdId, String name, Object value, MetricDataType dt)
            throws Exception {
        PropertySet props = new PropertySetBuilder()
                .addProperty("op", new PropertyValue(PropertyDataType.String, "write"))
                .createPropertySet();
        return new SparkplugBPayloadBuilder()
                .setUuid(cmdId).setTimestamp(new Date())
                .addMetric(new MetricBuilder(name, dt, value).properties(props).createMetric())
                .createPayload();
    }

    // ----- ① authz -----

    @Test void unlisted_command_is_applied_and_flagged_in_log_only() throws Exception {
        NcmdOpcUaBridgeTest.FakeApplier fake = new NcmdOpcUaBridgeTest.FakeApplier();
        NcmdResponse r = logOnly(fake).handle(NCMD_TOPIC, write("c-1", UNLISTED, 1.0, MetricDataType.Double));

        assertTrue(fake.writeCalled, "log-only must APPLY the command it would have denied");
        assertEquals(UNLISTED, fake.lastWriteNode);
        assertTrue(r.ok(), "the caller must see the real applier result, not a refusal");
        assertTrue(r.detail().startsWith("log-only would-deny: "),
                "the shadowed verdict must reach the caller too, not only the ops log: " + r.detail());
        assertTrue(r.detail().endsWith("| written+confirmed"),
                "the applier's own detail must survive the decoration: " + r.detail());
    }

    @Test void unlisted_command_is_still_denied_when_enforcing() throws Exception {
        NcmdOpcUaBridgeTest.FakeApplier fake = new NcmdOpcUaBridgeTest.FakeApplier();
        NcmdResponse r = enforcing(fake).handle(NCMD_TOPIC, write("c-2", UNLISTED, 1.0, MetricDataType.Double));

        assertFalse(fake.writeCalled, "the enforcing default must not have changed");
        assertFalse(r.ok());
        assertTrue(r.detail().startsWith("denied: "), r.detail());
    }

    // ----- ② conformance -----

    @Test void conformance_violation_is_applied_and_flagged_in_log_only() throws Exception {
        // Same fixture as NcmdOpcUaBridgeTest.above_max_denied_by_conformance: authz allows a type-ok
        // Rpm=9999, the governed envelope (Rpm ∈ [0,3000]) is what refuses it.
        UdtDefinition mixerDef = new UdtDefinition("Line1-Mixer", SemVer.parse("1.0.0"),
                List.of(new Member("Rpm", "Double", null, new Range(0, 3000)),
                        new Member("Temp", "Double", null, new Range(0, 450))),
                List.of(), null);
        ConformancePolicy mixerPolicy = new ConformancePolicy("Line1-Mixer-policy", "1.0.0",
                "Line1-Mixer", "1.0.0", new ConformancePolicy.Dial("envelope", null, null, null),
                List.of(), List.of(new NodeBinding(RPM, null, "Rpm")));

        NcmdOpcUaBridgeTest.FakeApplier fake = new NcmdOpcUaBridgeTest.FakeApplier();
        NcmdOpcUaBridge bridge = new NcmdOpcUaBridge(GROUP, EDGE, policy(), fake,
                mixerDef, mixerPolicy, null, true);
        NcmdResponse r = bridge.handle(NCMD_TOPIC, write("c-3", RPM, 9999.0, MetricDataType.Double));

        assertTrue(fake.writeCalled, "log-only covers ② conformance, not only ① authz");
        assertEquals(9999.0, fake.lastWriteValue);
        assertTrue(r.ok());
        assertTrue(r.detail().startsWith("log-only would-deny: "), r.detail());
    }

    // ----- what log-only must NOT do -----

    @Test void malformed_payload_is_still_rejected_in_log_only() throws Exception {
        // There is no command in a payload carrying no command metric, so there is nothing to let
        // through. Shadowing this would turn a decode failure into a no-op reported as success.
        NcmdOpcUaBridgeTest.FakeApplier fake = new NcmdOpcUaBridgeTest.FakeApplier();
        SparkplugBPayload empty = new SparkplugBPayloadBuilder()
                .setUuid("c-4").setTimestamp(new Date()).createPayload();

        NcmdResponse r = logOnly(fake).handle(NCMD_TOPIC, empty);

        assertFalse(r.ok());
        assertEquals("no command metric", r.detail());
        assertFalse(fake.writeCalled);
    }

    @Test void allowed_command_is_untouched_in_log_only() throws Exception {
        // A command that was going to be applied anyway must be indistinguishable from an enforcing
        // run — otherwise the decoration is noise on every line instead of a signal on a few.
        NcmdOpcUaBridgeTest.FakeApplier fake = new NcmdOpcUaBridgeTest.FakeApplier();
        NcmdResponse r = logOnly(fake).handle(NCMD_TOPIC, write("c-5", RPM, 1500.0, MetricDataType.Double));

        assertTrue(r.ok());
        assertEquals("written+confirmed", r.detail(), "no decoration when nothing would have been denied");
    }

    @Test void read_is_unaffected_by_log_only() throws Exception {
        // Reads bypass authorization in both modes — observation, not command.
        NcmdOpcUaBridgeTest.FakeApplier fake = new NcmdOpcUaBridgeTest.FakeApplier();
        NcmdResponse r = logOnly(fake).handle(QUERY_TOPIC, write("c-6", RPM, 0.0, MetricDataType.Double));

        assertTrue(fake.readCalled);
        assertFalse(fake.writeCalled);
        assertEquals("1500.0", r.value());
    }
}
