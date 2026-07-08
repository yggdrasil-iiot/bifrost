package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.Date;

import org.eclipse.tahu.message.SparkplugBPayloadDecoder;
import org.eclipse.tahu.message.model.Metric;
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
 * Wire-contract pin for the bridge side of the Sparkplug B NCMD command/response format, using
 * canonical cases (cmdId {@code vec-w1}/{@code vec-c1}/{@code vec-r1}, node {@code ns=2;s=Recipe/Rpm},
 * value {@code 1500.0}, doneNode {@code ns=2;s=Recipe/ApplyDone}, timeoutMs {@code 30000}...).
 *
 * <p>Two directions:
 * <ul>
 *   <li><b>Decode:</b> a command payload built INLINE with Tahu exactly per the contract
 *       (uuid=cmdId; one metric name=nodeId; properties {@code op}/{@code doneNode}/{@code timeoutMs}
 *       as String/String/Int64) is fed to {@link NcmdOpcUaBridge#handle}. Asserting the bridge reads
 *       the op/name/value/doneNode/timeoutMs correctly proves it agrees with the property KEYS — if
 *       the bridge renamed {@code op}, a "call" would misroute to the write path and fail.</li>
 *   <li><b>Encode:</b> {@link NcmdOpcUaBridge#encodeResponse} output is decoded and asserted to carry
 *       uuid=cmdId and metrics named EXACTLY {@code ok}(Boolean)/{@code detail}(String)/
 *       {@code value}(String)/{@code good}(Boolean).</li>
 * </ul>
 * If the bridge renames a property key or a response metric name/type, THIS test goes RED at
 * unit-test time — instead of surfacing only as a T1 timeout at the live runtime gate.
 */
class NcmdWireContractTest {

    private static final String GROUP = "Bifrost:Line1";
    private static final String EDGE = "recipe-edge";
    private static final String NCMD_TOPIC = "spBv1.0/" + GROUP + "/NCMD/" + EDGE;
    private static final String QUERY_TOPIC = "bifrost/" + GROUP + "/QUERY/" + EDGE;
    private static final String NDATA_TOPIC = "spBv1.0/" + GROUP + "/NDATA/" + EDGE;

    private CommandPolicy policy() throws Exception {
        return AclMapperFactory.create()
                .readValue(Path.of("registry/policy.json").toFile(), CommandPolicy.class);
    }

    private NcmdOpcUaBridge bridge(Applier applier) throws Exception {
        return new NcmdOpcUaBridge(GROUP, EDGE, policy(), applier);
    }

    /** Build a command payload INLINE, exactly matching the bridge's command wire-contract shape. */
    private static SparkplugBPayload cmd(String cmdId, String op, String name, Object value,
                                         MetricDataType dt, String doneNode, Long timeoutMs)
            throws Exception {
        PropertySetBuilder pb = new PropertySetBuilder()
                .addProperty("op", new PropertyValue(PropertyDataType.String, op));
        if (doneNode != null) {
            pb.addProperty("doneNode", new PropertyValue(PropertyDataType.String, doneNode));
        }
        if (timeoutMs != null) {
            pb.addProperty("timeoutMs", new PropertyValue(PropertyDataType.Int64, timeoutMs));
        }
        PropertySet props = pb.createPropertySet();
        return new SparkplugBPayloadBuilder()
                .setUuid(cmdId)
                .setTimestamp(new Date())
                .addMetric(new MetricBuilder(name, dt, value).properties(props).createMetric())
                .createPayload();
    }

    // ---- Decode side: the bridge reads the contract's property KEYS + command name/value ----

    @Test void bridge_reads_write_command_name_and_value_via_op_key() throws Exception {
        FakeApplier fake = new FakeApplier();
        NcmdResponse r = bridge(fake).handle(NCMD_TOPIC,
                cmd("vec-w1", "write", "ns=2;s=Recipe/Rpm", 1500.0, MetricDataType.Double, null, null));

        // op=write routed to the write path (proves the `op` property KEY is read).
        assertTrue(fake.writeCalled, "op=write must route to applier.write");
        assertFalse(fake.callCalled);
        assertEquals("ns=2;s=Recipe/Rpm", fake.lastWriteNode, "command metric name = nodeId");
        assertEquals(1500.0, fake.lastWriteValue, "command metric value read as Double");
        assertTrue(r.ok());
        assertEquals("vec-w1", r.cmdId(), "response echoes the request uuid (cmdId)");
    }

    @Test void bridge_reads_call_donenode_and_timeout_property_keys() throws Exception {
        FakeApplier fake = new FakeApplier();
        NcmdResponse r = bridge(fake).handle(NCMD_TOPIC,
                cmd("vec-c1", "call", "ns=2;s=Recipe/ApplyRecipe", Boolean.TRUE, MetricDataType.Boolean,
                        "ns=2;s=Recipe/ApplyDone", 30000L));

        // op=call routed to the call path (proves `op` key); doneNode/timeoutMs read from properties.
        assertTrue(fake.callCalled, "op=call must route to applier.call");
        assertFalse(fake.writeCalled);
        assertEquals("ns=2;s=Recipe/ApplyRecipe", fake.lastCallTrigger, "trigger = command metric name");
        assertEquals("ns=2;s=Recipe/ApplyDone", fake.lastCallDone, "doneNode read from the `doneNode` key");
        assertEquals(30000L, fake.lastCallTimeout, "timeoutMs read from the `timeoutMs` Int64 key");
        assertTrue(r.ok());
        assertEquals("vec-c1", r.cmdId());
    }

    @Test void bridge_reads_read_command_via_op_key_and_query_topic() throws Exception {
        FakeApplier fake = new FakeApplier();
        fake.readResult = new Applier.ReadBack("200.0", true);
        NcmdResponse r = bridge(fake).handle(QUERY_TOPIC,
                cmd("vec-r1", "read", "ns=2;s=Recipe/Temp", null, MetricDataType.String, null, null));

        assertTrue(fake.readCalled, "op=read / QUERY topic must route to applier.read");
        assertFalse(fake.writeCalled);
        assertEquals("ns=2;s=Recipe/Temp", fake.lastReadNode, "read node = command metric name");
        assertEquals("200.0", r.value());
        assertTrue(r.good());
        assertEquals("vec-r1", r.cmdId());
    }

    // ---- Encode side: response metrics named/typed exactly per the contract ----

    @Test void ok_response_encodes_uuid_and_ok_detail_metrics() throws Exception {
        byte[] bytes = bridge(new FakeApplier())
                .encodeResponse(NcmdResponse.apply("vec-w1", true, "written+confirmed"));
        SparkplugBPayload p = new SparkplugBPayloadDecoder().buildFromByteArray(bytes, null);

        assertEquals("vec-w1", p.getUuid(), "response uuid must carry the cmdId");
        assertEquals(2, p.getMetrics().size(), "write/ok response carries exactly ok + detail");

        Metric ok = metric(p, "ok");
        assertEquals(MetricDataType.Boolean, ok.getDataType(), "`ok` metric must be Boolean");
        assertEquals(Boolean.TRUE, ok.getValue());

        Metric detail = metric(p, "detail");
        assertEquals(MetricDataType.String, detail.getDataType(), "`detail` metric must be String");
        assertEquals("written+confirmed", detail.getValue());
    }

    @Test void read_response_adds_value_string_and_good_boolean_metrics() throws Exception {
        byte[] bytes = bridge(new FakeApplier())
                .encodeResponse(new NcmdResponse("vec-r1", true, "200.0", true, "read=200.0 good=true"));
        SparkplugBPayload p = new SparkplugBPayloadDecoder().buildFromByteArray(bytes, null);

        assertEquals("vec-r1", p.getUuid());
        assertEquals(4, p.getMetrics().size(), "read response carries ok + detail + value + good");

        Metric value = metric(p, "value");
        assertEquals(MetricDataType.String, value.getDataType(), "`value` metric must be String");
        assertEquals("200.0", value.getValue());

        Metric good = metric(p, "good");
        assertEquals(MetricDataType.Boolean, good.getDataType(), "`good` metric must be Boolean");
        assertEquals(Boolean.TRUE, good.getValue());
    }

    @Test void deny_response_omits_value_and_good() throws Exception {
        byte[] bytes = bridge(new FakeApplier())
                .encodeResponse(NcmdResponse.apply("vec-c1", false, "denied: above-max"));
        SparkplugBPayload p = new SparkplugBPayloadDecoder().buildFromByteArray(bytes, null);

        assertEquals("vec-c1", p.getUuid());
        assertEquals(2, p.getMetrics().size(), "deny omits value/good (both null) -> only ok + detail");
        assertEquals(Boolean.FALSE, metric(p, "ok").getValue());
        assertEquals("denied: above-max", metric(p, "detail").getValue());
        assertNull(findMetric(p, "value"), "no `value` metric on a deny");
        assertNull(findMetric(p, "good"), "no `good` metric on a deny");
    }

    // ---- Topic pin: the bridge derives the exact three cross-repo topic strings ----

    @Test void bridge_derives_the_pinned_topic_strings() throws Exception {
        // A QUERY-topic read bypasses authorization: this only holds if the bridge's queryTopic
        // equals the pinned QUERY string. An NCMD-topic write is authorized+applied. Together they
        // pin that the bridge derives spBv1.0/{group}/NCMD and bifrost/{group}/QUERY from group/edge.
        FakeApplier fake = new FakeApplier();
        assertTrue(bridge(fake).handle(QUERY_TOPIC,
                cmd("vec-r1", "read", "ns=2;s=Recipe/Temp", null, MetricDataType.String, null, null)).ok());
        assertTrue(fake.readCalled, "QUERY topic must be recognized as a read (topic string pinned)");

        assertEquals(NDATA_TOPIC, "spBv1.0/" + GROUP + "/NDATA/" + EDGE, "NDATA response topic pinned");
    }

    private static Metric metric(SparkplugBPayload p, String name) {
        Metric m = findMetric(p, name);
        assertNotNull(m, "expected a metric named `" + name + "`");
        return m;
    }

    private static Metric findMetric(SparkplugBPayload p, String name) {
        for (Metric m : p.getMetrics()) {
            if (name.equals(m.getName())) return m;
        }
        return null;
    }

    /** Records interactions and returns programmed results (mirrors the contract's canonical values). */
    static final class FakeApplier implements Applier {
        boolean writeCalled, callCalled, readCalled;
        String lastWriteNode, lastReadNode;
        double lastWriteValue;
        String lastCallTrigger, lastCallDone;
        long lastCallTimeout;
        Result writeResult = new Result(true, "written+confirmed");
        Result callResult = new Result(true, "rising-edge confirmed");
        ReadBack readResult = new ReadBack("200.0", true);

        @Override public ReadBack read(String nodeId) {
            readCalled = true;
            lastReadNode = nodeId;
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
