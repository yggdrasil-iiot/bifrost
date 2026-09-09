package dev.krillin.bifrost.heimdall;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttCallbackExtended;
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
import dev.krillin.bifrost.core.acl.CommandEnvelope;
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
public final class NcmdOpcUaBridge implements MqttCallbackExtended {

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

    /**
     * Bifrost's own liveness topic, carrying a retained "online"/"offline".
     *
     * <p>Deliberately NOT the Sparkplug NDEATH topic. In the spine
     * ({@code scripts/run-yggdrasil-spine-gate.sh}) Muninn is the node that births this
     * group/edge, and two components birthing one edge is a protocol error rather than a detail.
     * Deciding who owns the Sparkplug node identity for an edge that Heimdall commands and Muninn
     * feeds is a larger question than this change. This follows the existing
     * {@code bifrost/.../QUERY/...} convention and needs no ownership decision.
     */
    private final String statusTopic;

    private final SparkplugBPayloadEncoder encoder = new SparkplugBPayloadEncoder();
    private final SparkplugBPayloadDecoder decoder = new SparkplugBPayloadDecoder();
    private MqttClient client;

    /** Per-node ordered, bounded dispatch for applies. See {@link CommandExecutor}. */
    private final CommandExecutor executor;

    /** Counters + the /healthz state. Owned by the caller in production so main can serve it. */
    private final EdgeHealth health;

    /**
     * R1: require every command to carry a verified signature (env {@code REQUIRE_SIGNED_COMMAND},
     * default OFF). OFF is the pre-R1 path exactly, which is what keeps the seven existing NCMD
     * gates meaningful.
     */
    private final boolean requireSignedCommand;

    /** Principal name to registered public key, or null for an unregistered name. */
    private final java.util.function.Function<String, java.util.List<java.security.PublicKey>> trustAnchor;

    /**
     * Recently-seen command ids, for replay refusal. Consulted only when the bar is on.
     *
     * <p><b>Synchronized because the apply path is striped.</b> Commands for different nodes run on
     * different {@link CommandExecutor} threads, so this map is genuinely written concurrently.
     *
     * <p><b>This is a window, not a proof.</b> An attacker who waits until an id has aged out can
     * replay; a bridge restart empties it entirely; and it does nothing for a payload with no
     * command id, which is why a blank one is refused outright instead. Durable freshness needs a
     * timestamp and a clock the site trusts, and OT sites frequently have neither.
     */
    private final java.util.Map<String, Boolean> seenCmdIds;

    /**
     * R2: the tamper-evident record of commands. Null means no record, which is the pre-R2
     * behaviour and the default.
     */
    private final dev.krillin.bifrost.core.command.CommandLedger commandLedger;

    /**
     * When on, an unwritable INTENT entry refuses the command rather than letting it reach the plant
     * unrecorded. A failed OUTCOME entry cannot refuse anything — the plant has already moved — so it
     * is logged loudly and counted instead. That asymmetry is inherent, not an oversight.
     */
    private final boolean requireCommandLedger;

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
        this(group, edge, policy, applier, conformanceDef, conformancePolicy, activeRecipe, logOnly,
                health, applyThreads, applyQueueDepth, false, 1024, null);
    }

    /**
     * The widest constructor. {@code requireSignedCommand} is the R1 bar; {@code trustAnchor} maps a
     * principal name to its registered Ed25519 public key, or null when it is not registered.
     *
     * <p>The anchor is a function rather than an {@code AuthorizedKeys} because that is the shape
     * {@code CommandEnvelope.verify} wants, and because it keeps the resolution decision with the
     * caller: {@code NcmdOpcUaBridgeMain} loads the file ONCE at startup, so revocation latency is
     * the next edge restart. That is the boundary {@code ENTERPRISE.md} section 2 already documents
     * for policy and the ledger, rather than a second and quieter rule invented here.
     */
    public NcmdOpcUaBridge(String group, String edge, CommandPolicy policy, Applier applier,
                           UdtDefinition conformanceDef, ConformancePolicy conformancePolicy, MasterSpec activeRecipe,
                           boolean logOnly, EdgeHealth health, int applyThreads, int applyQueueDepth,
                           boolean requireSignedCommand, int replayWindow,
                           java.util.function.Function<String, java.util.List<java.security.PublicKey>> trustAnchor) {
        this(group, edge, policy, applier, conformanceDef, conformancePolicy, activeRecipe, logOnly,
                health, applyThreads, applyQueueDepth, requireSignedCommand, replayWindow, trustAnchor,
                null, false);
    }

    /**
     * The widest constructor. {@code commandLedger} is nullable — null is the pre-R2 behaviour, no
     * record at all. {@code requireCommandLedger} decides what an unwritable INTENT entry means: with
     * it on, the command is refused and the plant is never touched.
     */
    public NcmdOpcUaBridge(String group, String edge, CommandPolicy policy, Applier applier,
                           UdtDefinition conformanceDef, ConformancePolicy conformancePolicy, MasterSpec activeRecipe,
                           boolean logOnly, EdgeHealth health, int applyThreads, int applyQueueDepth,
                           boolean requireSignedCommand, int replayWindow,
                           java.util.function.Function<String, java.util.List<java.security.PublicKey>> trustAnchor,
                           dev.krillin.bifrost.core.command.CommandLedger commandLedger,
                           boolean requireCommandLedger) {
        this.commandLedger = commandLedger;
        this.requireCommandLedger = requireCommandLedger;
        this.requireSignedCommand = requireSignedCommand;
        this.trustAnchor = trustAnchor;
        this.seenCmdIds = java.util.Collections.synchronizedMap(
                new java.util.LinkedHashMap<String, Boolean>(16, 0.75f, true) {
                    @Override protected boolean removeEldestEntry(java.util.Map.Entry<String, Boolean> e) {
                        return size() > Math.max(1, replayWindow);
                    }
                });
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
        this.statusTopic = "bifrost/" + group + "/STATUS/" + edge;
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
            record(cmdId, null, null, null, null, "intent", "malformed", "no command metric");
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

        // ----- R1: the signature bar, before any verdict is formed -----
        //
        // Every refusal below returns DIRECTLY and must never be routed through refuse(). Under
        // ENFORCEMENT_LOG_ONLY, refuse() returns null and its caller falls through and APPLIES, so a
        // shadowed unsigned command would reach authorize() with a null subject and skip the
        // principal check entirely. That is not what log-only is for: log-only inverts policy
        // VERDICTS so a rollout cannot stop the line, and this bar is an authentication question --
        // whether there is an identity to judge at all. It is the same orthogonality that
        // NcmdOpcUaBridgeMain already documents for the REQUIRE_*_ACTIVATION bars, and the same
        // reasoning that keeps the malformed-payload rejection above outside log-only.
        String subject = null;
        if (requireSignedCommand) {
            String sub = propString(props, "sub");
            String sig = propString(props, "sig");
            if (cmdId == null || cmdId.isBlank() || sub == null || sub.isBlank() || sig == null || sig.isBlank()) {
                // A blank cmdId is refused here too: with nothing to bind, one signature would be
                // valid for every other id-less payload - a replay hole, not an inconvenience.
                return refuseUnverified(cmdId, name, value, "command.unsigned");
            }
            if (seenCmdIds.putIfAbsent(cmdId, Boolean.TRUE) != null) {
                return refuseUnverified(cmdId, name, value, "command.replay");
            }
            CommandEnvelope.Verdict v = CommandEnvelope.verify(
                    trustAnchor == null ? n -> null : trustAnchor,
                    sub, sig, group, edge, cmdId, name, value, dataType);
            if (v == CommandEnvelope.Verdict.UNKNOWN_PRINCIPAL) {
                return refuseUnverified(cmdId, name, value, "command.principal.unknown");
            }
            if (v != CommandEnvelope.Verdict.OK) {
                return refuseUnverified(cmdId, name, value, "command.sig.invalid");
            }
            subject = sub;
        }

        // The first reason this command WOULD have been refused, when log-only let it through anyway.
        // Null in the normal enforcing case, which is what keeps the response identical to before.
        String shadowed = null;

        CommandRequest cr = new CommandRequest(new Target(group, edge, null), name, value, dataType, subject);
        Decision d = authorizer.authorize(policy, cr);
        if (!d.allowed()) {
            NcmdResponse refused = refuse(cmdId, name, value, d.reason());
            if (refused != null) {
                record(cmdId, subject, name, value, dataType, "intent", "denied", d.reason());
                return refused;
            }
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
                        if (refused != null) {
                            record(cmdId, subject, name, value, dataType, "intent", "denied", reason);
                            return refused;
                        }
                        if (shadowed == null) shadowed = reason;
                    }
                } catch (PlantUnreachableException unreachable) {
                    // NOT a verdict. The plant is not visible, so ② could not be evaluated at all.
                    // Reported separately so an operator is never sent to look at the model because
                    // a server restarted, and counted separately so /healthz can go unhealthy.
                    //
                    // The log line is printed in BOTH unreachable catches on purpose. Today's
                    // shipped fixture (registry/conformance/Line1-Mixer/1.0.0.json) has no cross
                    // constraints, so readDouble is never called there and an outage always lands
                    // on the apply path below; logging only there would make the resilience gate
                    // green for a reason unrelated to this branch.
                    System.out.println("[BRIDGE] UNREACHABLE cmd=" + name + " reason=" + unreachable.getMessage());
                    record(cmdId, subject, name, value, dataType, "intent", "unreachable",
                            unreachable.getMessage());
                    health.plantUnreachable();
                    return NcmdResponse.apply(cmdId, false,
                            detail(shadowed, "plant-unreachable: " + unreachable.getMessage()));
                } catch (Exception confEx) {   // fail-closed: any conformance/read error DENIES
                    String reason = "conformance-error: " + confEx.getMessage();
                    NcmdResponse refused = refuse(cmdId, name, value, reason);
                    if (refused != null) {
                        record(cmdId, subject, name, value, dataType, "intent", "denied", reason);
                        return NcmdResponse.apply(cmdId, false, "denied: conformance-error");
                    }
                    if (shadowed == null) shadowed = reason;
                }
            }
        }

        // THE intent entry. Written before the applier so that "no command reaches the plant
        // without a record" is a claim this code can keep. With REQUIRE_COMMAND_LEDGER on, a failed
        // append refuses here - and refuses DIRECTLY, not through refuse(), for the same reason R1's
        // signature bar does: log-only inverts verdicts, and "I could not record this" is not one.
        if (!record(cmdId, subject, name, value, dataType, "intent", "pending", shadowed)
                && requireCommandLedger) {
            return refuseUnverified(cmdId, name, value, "command.ledger.unwritable");
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
            // The outcome cannot refuse anything: the plant has already moved.
            record(cmdId, subject, name, value, dataType, "outcome",
                    r.ok() ? "applied" : "apply-failed", r.ok() ? null : r.detail());
            System.out.println("[BRIDGE] APPLY cmd=" + name + " ok=" + r.ok());
            return NcmdResponse.apply(cmdId, r.ok(), detail(shadowed, r.detail()));
        } catch (PlantUnreachableException unreachable) {
            // Same rule as the ② catch above: a refusal, but never reported as a verdict.
            System.out.println("[BRIDGE] UNREACHABLE cmd=" + name + " reason=" + unreachable.getMessage());
            record(cmdId, subject, name, value, dataType, "outcome", "unreachable", unreachable.getMessage());
            health.plantUnreachable();
            return NcmdResponse.apply(cmdId, false,
                    detail(shadowed, "plant-unreachable: " + unreachable.getMessage()));
        } catch (Exception e) {
            record(cmdId, subject, name, value, dataType, "outcome", "apply-error", e.getMessage());
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
    /**
     * Refuse a command that could not be authenticated. <b>Never shadowed by log-only.</b>
     *
     * <p>Deliberately not {@link #refuse}: that one returns null under log-only so the caller
     * applies the command anyway, which is right for a policy verdict during a rollout and wrong
     * here. There is no identity to judge, so there is no verdict to shadow. Same reason the
     * malformed-payload rejection sits outside log-only.
     */
    /**
     * Append one fact to the command ledger.
     *
     * <p>Recording is scattered across {@code handle()}'s return sites rather than centralised,
     * because the outcomes are not alternatives: under log-only a command is BOTH would-denied and
     * applied, and {@code applied} is only knowable after the applier has already moved the plant.
     * Two entries per applied command is the price of both facts being true.
     *
     * @return false when the append failed, so an intent site can refuse before touching the plant
     */
    private boolean record(String cmdId, String subject, String name, Object value, String dataType,
                           String phase, String outcome, String reason) {
        if (commandLedger == null) {
            return true;
        }
        try {
            commandLedger.append(new dev.krillin.bifrost.core.command.CommandEvent(
                    group, edge, cmdId, subject, name,
                    value == null ? null : String.valueOf(value), dataType,
                    phase, outcome, reason, java.time.Instant.now().toString()));
            return true;
        } catch (Exception e) {
            System.out.println("[BRIDGE] LEDGER-WRITE-FAILED phase=" + phase + " cmd=" + name + ": " + e);
            return false;
        }
    }

    private NcmdResponse refuseUnverified(String cmdId, String name, Object value, String reason) {
        // No subject: that is what "unverified" means here.
        record(cmdId, null, name, value, null, "intent", "unverified", reason);
        health.denied();
        System.out.println("[BRIDGE] DENY cmd=" + name + " val=" + value + " reason=" + reason);
        return NcmdResponse.apply(cmdId, false, "denied: " + reason);
    }

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
        opts.setAutomaticReconnect(true);
        // Explicit, because the will's latency IS this value: the broker cannot declare us dead
        // until the keepalive lapses, and the 60s default makes a death take ~90s to appear.
        opts.setKeepAliveInterval(20);
        // The will is the whole liveness story: if this process dies, is partitioned, or hangs past
        // the keepalive, the BROKER publishes "offline" on our behalf. Nothing else can report a
        // death that the dying process did not notice. See statusTopic's javadoc for why this is
        // not Sparkplug NDEATH.
        opts.setWill(statusTopic, "offline".getBytes(StandardCharsets.UTF_8), 1, true);
        client.connect(opts);
        subscribeAll();
        publishStatus("online");
        System.out.println("[BRIDGE] subscribed NCMD=" + ncmdTopic + " QUERY=" + queryTopic
                + " (policy rules=" + policy.rules().size() + ")");
    }

    private void subscribeAll() throws Exception {
        client.subscribe(ncmdTopic, 1);
        client.subscribe(queryTopic, 1);
    }

    private void publishStatus(String state) {
        try {
            client.publish(statusTopic, state.getBytes(StandardCharsets.UTF_8), 1, true);
        } catch (Exception e) {
            System.out.println("[BRIDGE] status publish failed (" + state + "): " + e);
        }
    }

    @Override
    public void connectComplete(boolean reconnect, String serverURI) {
        health.brokerConnected();
        if (!reconnect) {
            return;   // the initial connect already subscribed and announced
        }
        // LOAD-BEARING. cleanSession(true) means the broker dropped our subscriptions along with
        // the session, and automatic reconnect does not restore them. Without this the bridge comes
        // back CONNECTED and deaf — which reads healthy in the log, and is worse than the outage.
        //
        // This runs on Paho's callback thread and both calls below are synchronous, so the callback
        // is blocked until they ack. That is the standard resubscribe pattern and the window is
        // bounded, but it is why nothing heavier belongs here.
        try {
            subscribeAll();
            publishStatus("online");
            System.out.println("[BRIDGE] reconnected to " + serverURI + ", resubscribed");
        } catch (Exception e) {
            System.out.println("[BRIDGE] RESUBSCRIBE FAILED after reconnect: " + e);
        }
    }

    public void close() throws Exception {
        executor.close();
        if (client != null) {
            if (client.isConnected()) {
                // An orderly stop is not a death: say so ourselves rather than leaving the will to
                // report it. A hard kill still leaves the broker to publish "offline" for us.
                publishStatus("offline");
                client.disconnect();
            }
            client.close();
        }
    }

    @Override public void connectionLost(Throwable cause) {
        health.brokerDisconnected();
        System.out.println("[BRIDGE] connection lost: " + cause + " (auto-reconnect armed)");
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
