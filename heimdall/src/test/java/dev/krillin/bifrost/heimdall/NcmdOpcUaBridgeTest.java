package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.Date;

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

/**
 * The bridge core: decode ONE authorizable command metric, authorize deny-by-default at the edge,
 * apply through the injected {@link Applier}, and produce a correlated {@link NcmdResponse}.
 * No broker or OPC-UA server is involved — a {@link FakeApplier} records interactions.
 */
class NcmdOpcUaBridgeTest {

    private static final String GROUP = "Koshei:Line1";
    private static final String EDGE = "recipe-edge";
    private static final String NCMD_TOPIC = "spBv1.0/" + GROUP + "/NCMD/" + EDGE;
    private static final String QUERY_TOPIC = "koshei/" + GROUP + "/QUERY/" + EDGE;

    private CommandPolicy policy() throws Exception {
        return AclMapperFactory.create()
                .readValue(Path.of("registry/koshei-line1-policy.json").toFile(), CommandPolicy.class);
    }

    private NcmdOpcUaBridge bridge(Applier applier) throws Exception {
        return new NcmdOpcUaBridge(GROUP, EDGE, policy(), applier);
    }

    /** Build a single-command-metric NCMD payload mirroring koshei's SpbCodec.encodeCommand. */
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

    /** Records interactions and returns programmed results. */
    static final class FakeApplier implements Applier {
        boolean writeCalled, callCalled, readCalled;
        String lastWriteNode;
        double lastWriteValue;
        String lastCallTrigger, lastCallDone;
        long lastCallTimeout;
        Result writeResult = new Result(true, "written+confirmed");
        Result callResult = new Result(true, "rising-edge confirmed");
        ReadBack readResult = new ReadBack("1500.0", true);

        @Override public ReadBack read(String nodeId) {
            readCalled = true;
            return readResult;
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
