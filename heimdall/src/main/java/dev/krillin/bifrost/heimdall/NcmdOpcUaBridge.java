package dev.krillin.bifrost.heimdall;

import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;
import org.eclipse.tahu.message.SparkplugBPayloadDecoder;
import org.eclipse.tahu.message.SparkplugBPayloadEncoder;
import org.eclipse.tahu.message.model.Metric;
import org.eclipse.tahu.message.model.Metric.MetricBuilder;
import org.eclipse.tahu.message.model.MetricDataType;
import org.eclipse.tahu.message.model.PropertySet;
import org.eclipse.tahu.message.model.PropertyValue;
import org.eclipse.tahu.message.model.SparkplugBPayload;
import org.eclipse.tahu.message.model.SparkplugBPayload.SparkplugBPayloadBuilder;

import dev.krillin.bifrost.core.acl.CommandAuthorizer;
import dev.krillin.bifrost.core.acl.CommandPolicy;
import dev.krillin.bifrost.core.acl.CommandRequest;
import dev.krillin.bifrost.core.acl.Decision;
import dev.krillin.bifrost.core.acl.Target;
import dev.krillin.bifrost.core.conformance.ConformanceEvaluator;
import dev.krillin.bifrost.core.conformance.ConformancePolicy;
import dev.krillin.bifrost.core.conformance.ConformanceVerdict;
import dev.krillin.bifrost.core.conformance.CrossConstraint;
import dev.krillin.bifrost.core.conformance.NodeBinding;
import dev.krillin.bifrost.core.schema.MasterSpec;
import dev.krillin.bifrost.core.schema.Member;
import dev.krillin.bifrost.core.schema.Setpoint;
import dev.krillin.bifrost.core.schema.UdtDefinition;

/**
 * Self-bridge: receives Sparkplug NCMD commands over MQTT, authorizes them deny-by-default at the
 * edge, applies them to OPC-UA via an injected {@link Applier}, confirms by read-back, and
 * publishes a correlated Sparkplug NDATA response.
 *
 * <p>The core is the pure, broker-free {@link #handle(String, SparkplugBPayload)} — unit-tested with
 * a fake applier + the real {@link CommandAuthorizer}/policy. The Paho wiring ({@link #connect},
 * {@link #messageArrived}) is a thin shell that decodes, dispatches {@code handle} off the callback
 * thread, and publishes the encoded response. The QUERY topic and response encoding follow
 * Heimdall's own Sparkplug command/response wire contract: property keys {@code op}/
 * {@code doneNode}/{@code timeoutMs}, response metrics {@code ok}/{@code value}/{@code good}/
 * {@code detail}.
 */
public final class NcmdOpcUaBridge implements MqttCallback {

    private final String group;
    private final String edge;
    private final CommandPolicy policy;
    private final Applier applier;
    private final CommandAuthorizer authorizer = new CommandAuthorizer();

    // Governed conformance deps, loaded at startup (nullable => ② conformance OFF; pure authz).
    // Loaded and stored here in B1; the ② check that consumes them is wired in B2.
    private final UdtDefinition conformanceDef;
    private final ConformancePolicy conformancePolicy;
    private final MasterSpec activeRecipe;

    private final String ncmdTopic;
    private final String queryTopic;
    private final String ndataTopic;

    private final SparkplugBPayloadEncoder encoder = new SparkplugBPayloadEncoder();
    private final SparkplugBPayloadDecoder decoder = new SparkplugBPayloadDecoder();
    private MqttClient client;

    public NcmdOpcUaBridge(String group, String edge, CommandPolicy policy, Applier applier,
                           UdtDefinition conformanceDef, ConformancePolicy conformancePolicy, MasterSpec activeRecipe) {
        this.group = group;
        this.edge = edge;
        this.policy = policy;
        this.applier = applier;
        this.conformanceDef = conformanceDef;
        this.conformancePolicy = conformancePolicy;
        this.activeRecipe = activeRecipe;
        this.ncmdTopic = "spBv1.0/" + group + "/NCMD/" + edge;
        this.queryTopic = "bifrost/" + group + "/QUERY/" + edge;
        this.ndataTopic = "spBv1.0/" + group + "/NDATA/" + edge;
    }

    // ----- pure core (no broker / no live OPC-UA) -----

    /**
     * Decode the single command metric, authorize (deny-by-default) unless it is a read, apply
     * through the {@link Applier}, and return the correlated response. Reads (QUERY topic or
     * {@code op=read}) bypass authorization — observation, not command.
     */
    public NcmdResponse handle(String topic, SparkplugBPayload req) {
        String cmdId = req.getUuid();
        if (req.getMetrics() == null || req.getMetrics().isEmpty()) {
            // Fail-closed: a malformed payload carrying no command metric is rejected, not crashed.
            return new NcmdResponse(cmdId, false, null, false, "no command metric");
        }
        Metric m = req.getMetrics().get(0);
        String name = m.getName();
        Object value = m.getValue();
        String dataType = m.getDataType().toString();

        PropertySet props = m.getProperties();
        String op = propString(props, "op");
        String doneNode = propString(props, "doneNode");
        long timeoutMs = propLong(props, "timeoutMs", 30_000L);

        boolean isRead = topic.equals(queryTopic) || "read".equals(op);
        if (isRead) {
            try {
                Applier.ReadBack rb = applier.read(name);
                return NcmdResponse.read(cmdId, rb.value(), rb.good());
            } catch (Exception e) {
                return new NcmdResponse(cmdId, false, null, false, "read error: " + e.getMessage());
            }
        }

        CommandRequest cr = new CommandRequest(new Target(group, edge, null), name, value, dataType);
        Decision d = authorizer.authorize(policy, cr);
        if (!d.allowed()) {
            System.out.println("[BRIDGE] DENY cmd=" + name + " val=" + value + " reason=" + d.reason());
            return NcmdResponse.apply(cmdId, false, "denied: " + d.reason());
        }

        // ① authz already passed (d.allowed()). ② conformance (opt-in: only when a policy is loaded):
        if (conformancePolicy != null && conformanceDef != null) {
            NodeBinding binding = conformancePolicy.nodeBindings().stream()
                    .filter(b -> name.equals(b.opcNodeId())).findFirst().orElse(null);
            if (binding != null) {
                try {
                    List<Setpoint> state = new ArrayList<>();
                    state.add(new Setpoint(binding.member(), dataType, ((Number) value).doubleValue()));
                    Set<String> needed = new LinkedHashSet<>();
                    for (CrossConstraint c : conformancePolicy.crossConstraints()) {
                        needed.add(c.ifMember()); needed.add(c.thenMember());
                    }
                    needed.remove(binding.member());
                    for (String sibMember : needed) {
                        NodeBinding sb = conformancePolicy.nodeBindings().stream()
                                .filter(b -> sibMember.equals(b.member()) && b.readNodeId() != null).findFirst().orElse(null);
                        // Fail-closed: a needed cross-member with no numeric readNodeId cannot be verified,
                        // so DON'T silently skip it (that would leave the antecedent absent => not-triggered => fail-open).
                        if (sb == null) throw new IllegalStateException(
                                "cross-constraint member '" + sibMember + "' has no readNodeId binding — cannot verify");
                        // Derive the sibling's type from the governed model (not hardcoded "Double") so a
                        // non-Double numeric sibling doesn't spuriously trip spec.type.mismatch.
                        String sibType = conformanceDef.members().stream()
                                .filter(dm -> dm.name().equals(sibMember)).map(Member::type)
                                .findFirst().orElse("Double");
                        state.add(new Setpoint(sibMember, sibType, applier.readDouble(sb.readNodeId())));
                    }
                    ConformanceVerdict cv = new ConformanceEvaluator()
                            .evaluate(conformanceDef, conformancePolicy, activeRecipe, state);
                    if (!cv.ok()) {
                        String reason = cv.violations().get(0).rule() + ": " + cv.violations().get(0).detail();
                        System.out.println("[BRIDGE] DENY cmd=" + name + " val=" + value + " reason=" + reason);
                        return NcmdResponse.apply(cmdId, false, "denied: " + reason);
                    }
                } catch (Exception confEx) {   // fail-closed: any conformance/read error DENIES
                    System.out.println("[BRIDGE] DENY cmd=" + name + " val=" + value + " reason=conformance-error: " + confEx.getMessage());
                    return NcmdResponse.apply(cmdId, false, "denied: conformance-error");
                }
            }
        }

        try {
            Applier.Result r;
            if ("call".equals(op)) {
                r = applier.call(name, doneNode, timeoutMs);
            } else {
                r = applier.write(name, ((Number) value).doubleValue());
            }
            System.out.println("[BRIDGE] APPLY cmd=" + name + " ok=" + r.ok());
            return NcmdResponse.apply(cmdId, r.ok(), r.detail());
        } catch (Exception e) {
            System.out.println("[BRIDGE] APPLY cmd=" + name + " ok=false");
            return NcmdResponse.apply(cmdId, false, "apply error: " + e.getMessage());
        }
    }

    // ----- Paho shell (exercised only by the live gate) -----

    public void connect(String broker) throws Exception {
        client = new MqttClient(broker, "bifrost-ncmd-bridge", new MemoryPersistence());
        client.setCallback(this);
        MqttConnectOptions opts = new MqttConnectOptions();
        opts.setCleanSession(true);
        client.connect(opts);
        client.subscribe(ncmdTopic, 1);
        client.subscribe(queryTopic, 1);
        System.out.println("[BRIDGE] subscribed NCMD=" + ncmdTopic + " QUERY=" + queryTopic
                + " (policy rules=" + policy.rules().size() + ")");
    }

    public void close() throws Exception {
        if (client != null) {
            if (client.isConnected()) client.disconnect();
            client.close();
        }
    }

    @Override public void connectionLost(Throwable cause) {
        System.out.println("[BRIDGE] connection lost: " + cause);
    }

    @Override public void deliveryComplete(IMqttDeliveryToken token) { }

    @Override public void messageArrived(String topic, MqttMessage message) {
        // Publishing from the MQTT callback thread is not allowed; dispatch off-thread.
        byte[] payload = message.getPayload();
        new Thread(() -> {
            try {
                SparkplugBPayload req = decoder.buildFromByteArray(payload, null);
                NcmdResponse resp = handle(topic, req);
                client.publish(ndataTopic, encodeResponse(resp), 1, false);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }

    /** Encode a response payload per Heimdall's response wire contract (metric names/types below). */
    byte[] encodeResponse(NcmdResponse r) throws Exception {
        SparkplugBPayloadBuilder b = new SparkplugBPayloadBuilder()
                .setUuid(r.cmdId())
                .setTimestamp(new Date())
                .addMetric(new MetricBuilder("ok", MetricDataType.Boolean, r.ok()).createMetric())
                .addMetric(new MetricBuilder("detail", MetricDataType.String, r.detail()).createMetric());
        if (r.value() != null) {
            b.addMetric(new MetricBuilder("value", MetricDataType.String, r.value()).createMetric());
        }
        if (r.good() != null) {
            b.addMetric(new MetricBuilder("good", MetricDataType.Boolean, r.good()).createMetric());
        }
        return encoder.getBytes(b.createPayload(), false);
    }

    private static String propString(PropertySet props, String key) {
        if (props == null) return null;
        PropertyValue pv = props.getPropertyValue(key);
        if (pv == null || pv.getValue() == null) return null;
        return pv.getValue().toString();
    }

    private static long propLong(PropertySet props, String key, long dflt) {
        if (props == null) return dflt;
        PropertyValue pv = props.getPropertyValue(key);
        if (pv == null || !(pv.getValue() instanceof Number n)) return dflt;
        return n.longValue();
    }
}
