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

    /**
     * Rollout mode (env {@code ENFORCEMENT_LOG_ONLY}, default OFF). When ON, a command that ①authz or
     * ②conformance would refuse is logged as {@code LOG-ONLY would-deny} and then APPLIED anyway.
     * It exists so an edge can be introduced at a running plant without the possibility of stopping
     * the line on day one (see {@code docs/ADOPTION.md} phase 4); enforcement then arrives by
     * removing allowlist rules, not by flipping a switch.
     * <p>Deliberately NOT covered: the malformed-payload rejection below. There is no command in a
     * payload that carries no command metric, so there is nothing to let through — shadowing it would
     * turn a decode failure into a silent no-op reported as success.
     */
    private final boolean logOnly;

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

    /** Per-node ordered, bounded dispatch for applies. See {@link CommandExecutor}. */
    private final CommandExecutor executor;

    /** Counters + the /healthz state. Owned by the caller in production so main can serve it. */
    private final EdgeHealth health;

    /** Exposed so {@code NcmdOpcUaBridgeMain} can start the HTTP endpoint over the same instance. */
    public EdgeHealth health() {
        return health;
    }

    /** Enforcing bridge — the default everywhere except an explicit rollout deployment. */
    public NcmdOpcUaBridge(String group, String edge, CommandPolicy policy, Applier applier,
                           UdtDefinition conformanceDef, ConformancePolicy conformancePolicy, MasterSpec activeRecipe) {
        this(group, edge, policy, applier, conformanceDef, conformancePolicy, activeRecipe, false);
    }

    public NcmdOpcUaBridge(String group, String edge, CommandPolicy policy, Applier applier,
                           UdtDefinition conformanceDef, ConformancePolicy conformancePolicy, MasterSpec activeRecipe,
                           boolean logOnly) {
        this(group, edge, policy, applier, conformanceDef, conformancePolicy, activeRecipe, logOnly,
                new EdgeHealth(), 4, 64);
    }

    /**
     * The widest constructor; the two above delegate here with the field defaults, so no existing
     * caller or test had to change when health and the apply stripes were added.
     */
    public NcmdOpcUaBridge(String group, String edge, CommandPolicy policy, Applier applier,
                           UdtDefinition conformanceDef, ConformancePolicy conformancePolicy, MasterSpec activeRecipe,
                           boolean logOnly, EdgeHealth health, int applyThreads, int applyQueueDepth) {
        this.health = health;
        this.executor = new CommandExecutor(applyThreads, applyQueueDepth);
        this.logOnly = logOnly;
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

        // The first reason this command WOULD have been refused, when log-only let it through anyway.
        // Null in the normal enforcing case, which is what keeps the response identical to before.
        String shadowed = null;

        CommandRequest cr = new CommandRequest(new Target(group, edge, null), name, value, dataType);
        Decision d = authorizer.authorize(policy, cr);
        if (!d.allowed()) {
            NcmdResponse refused = refuse(cmdId, name, value, d.reason());
            if (refused != null) return refused;
            shadowed = d.reason();
            // fall through to ② as well: in log-only the point is to learn every reason, not the first.
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
                                "cross-constraint member '" + sibMember + "' has no readNodeId binding - cannot verify");
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
                        NcmdResponse refused = refuse(cmdId, name, value, reason);
                        if (refused != null) return refused;
                        if (shadowed == null) shadowed = reason;
                    }
                } catch (Exception confEx) {   // fail-closed: any conformance/read error DENIES
                    String reason = "conformance-error: " + confEx.getMessage();
                    NcmdResponse refused = refuse(cmdId, name, value, reason);
                    if (refused != null) return NcmdResponse.apply(cmdId, false, "denied: conformance-error");
                    if (shadowed == null) shadowed = reason;
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
            if (r.ok()) {
                health.applied();
            }
            System.out.println("[BRIDGE] APPLY cmd=" + name + " ok=" + r.ok());
            return NcmdResponse.apply(cmdId, r.ok(), detail(shadowed, r.detail()));
        } catch (Exception e) {
            System.out.println("[BRIDGE] APPLY cmd=" + name + " ok=false");
            return NcmdResponse.apply(cmdId, false, detail(shadowed, "apply error: " + e.getMessage()));
        }
    }

    /**
     * Refuse a command, or — in log-only mode — record the verdict and let it through by returning
     * null. The two log tokens are deliberately distinct and neither is a substring of the other,
     * so a log scraper counting {@code [BRIDGE] DENY} never counts a shadowed verdict as a block.
     *
     * @return the refusal response, or {@code null} when the caller should carry on and apply.
     */
    private NcmdResponse refuse(String cmdId, String name, Object value, String reason) {
        if (logOnly) {
            System.out.println("[BRIDGE] LOG-ONLY would-deny cmd=" + name + " val=" + value + " reason=" + reason);
            return null;
        }
        // Counted only here, on the enforcing path. A log-only would-deny is not a denial, which is
        // the same reason the two log tokens above are kept distinct.
        health.denied();
        System.out.println("[BRIDGE] DENY cmd=" + name + " val=" + value + " reason=" + reason);
        return NcmdResponse.apply(cmdId, false, "denied: " + reason);
    }

    /**
     * The shadowed verdict also rides back on the response, not only into the ops log — the operator
     * who issued the command is the person who most needs to know it would have been blocked. The
     * APPLIED EFFECT is unchanged; only this string differs from an enforcing run.
     */
    private static String detail(String shadowed, String applied) {
        return shadowed == null ? applied : "log-only would-deny: " + shadowed + " | " + applied;
    }

    // ----- Paho shell (exercised only by the live gate) -----

    /**
     * MQTT client id for this edge. It MUST be per-edge: two bridges sharing an id take each
     * other's session in a loop, which is exactly what the previous constant caused. ':' and '/'
     * are folded because a group such as "Bifrost:Line1" carries the Sparkplug topic separator,
     * which brokers reject inside a client id.
     *
     * <p>The result can exceed the 23 characters MQTT 3.1 guaranteed; 3.1.1 removed that limit and
     * HiveMQ accepts it. If another broker is ever targeted, this is the line to shorten.
     */
    static String clientId(String group, String edge) {
        return ("heimdall-" + group + "-" + edge).replaceAll("[:/]", "-");
    }

    public void connect(String broker) throws Exception {
        client = new MqttClient(broker, clientId(group, edge), new MemoryPersistence());
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
        executor.close();
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
        // Publishing from the MQTT callback thread is not allowed; dispatch off-thread. The stripe
        // key is the command's node id, so two setpoints for one node keep their arrival order.
        byte[] payload = message.getPayload();
        final SparkplugBPayload req;
        try {
            req = decoder.buildFromByteArray(payload, null);
        } catch (Exception decodeFailure) {
            // Previously this threw on a throwaway thread and printed a stack trace with no context.
            System.out.println("[BRIDGE] DROP undecodable payload on " + topic + ": " + decodeFailure);
            return;
        }
        String stripeKey = (req.getMetrics() == null || req.getMetrics().isEmpty())
                ? "" : String.valueOf(req.getMetrics().get(0).getName());
        boolean accepted = executor.submit(stripeKey, () -> {
            try {
                NcmdResponse resp = handle(topic, req);
                client.publish(ndataTopic, encodeResponse(resp), 1, false);
            } catch (Exception e) {
                System.out.println("[BRIDGE] response publish failed for " + stripeKey + ": " + e);
            }
        });
        if (!accepted) {
            System.out.println("[BRIDGE] OVERLOAD cmd=" + stripeKey + " - queue full, command refused");
            try {
                client.publish(ndataTopic, encodeResponse(overloaded(req.getUuid())), 1, false);
            } catch (Exception e) {
                System.out.println("[BRIDGE] overload response publish failed: " + e);
            }
        }
    }

    /**
     * The overload refusal, extracted so a unit test can assert its wording without a broker.
     * A dropped command that nobody is told about is worse than a refused one.
     */
    static NcmdResponse overloaded(String cmdId) {
        return NcmdResponse.apply(cmdId, false, "overloaded: edge queue full");
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
