package dev.krillin.bifrost.heimdall;

import static dev.krillin.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.krillin.bifrost.core.acl.AclMapperFactory;
import dev.krillin.bifrost.core.acl.CommandPolicy;
import dev.krillin.bifrost.core.acl.opa.OpaMethodAuthorizer;
import dev.krillin.bifrost.core.command.CommandLedger;
import dev.krillin.bifrost.core.command.CommandLedgerEntry;
import dev.krillin.bifrost.core.command.CommandProposal;
import dev.krillin.bifrost.core.identity.AuthorizedKey;
import dev.krillin.bifrost.core.identity.Dsse;
import dev.krillin.bifrost.core.identity.Ed25519Keys;
import dev.krillin.bifrost.core.mapping.MappingRegistry;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import org.eclipse.tahu.message.model.Metric.MetricBuilder;
import org.eclipse.tahu.message.model.MetricDataType;
import org.eclipse.tahu.message.model.PropertyDataType;
import org.eclipse.tahu.message.model.PropertySet.PropertySetBuilder;
import org.eclipse.tahu.message.model.PropertyValue;
import org.eclipse.tahu.message.model.SparkplugBPayload;
import org.eclipse.tahu.message.model.SparkplugBPayload.SparkplugBPayloadBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The op=method path through the real bridge, registry, ledger and compiled OPA policy, with a fake
 * plant: the nine checks refuse in order with their reason codes, nothing before the reservation
 * consumes a cmdId, and once reserved a cmdId is never executed again.
 */
class NcmdBridgeMethodTest {
    static final String GROUP = "Bifrost:Line1", EDGE = "recipe-edge";
    static final String NCMD = "spBv1.0/" + GROUP + "/NCMD/" + EDGE;
    static final String OBJECT = "nsu=urn:bifrost:opcua:sim;s=Line1/Mixer1", METHOD = OBJECT + ".SetTemperature";
    static final String TEMP = OBJECT + ".Temp";

    static final class MovableClock extends Clock {
        Instant now = Instant.parse("2026-11-02T10:00:00Z");
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }

    /** A plant whose precondition sample and Method answer the test sets. */
    static final class FakePlant implements Applier {
        final MovableClock clock;
        boolean good = true;
        long ageMs = 1000;
        Boolean methodOk = true;
        int calls;
        final List<String> sampled = new ArrayList<>();
        FakePlant(MovableClock clock) { this.clock = clock; }
        @Override public ReadBack read(String nodeId) { return new ReadBack("0", true); }
        @Override public double readDouble(String nodeId) { return 0; }
        @Override public Result write(String nodeId, double value) { throw new AssertionError("the Method path never writes"); }
        @Override public Result call(String t, String d, long ms) { throw new AssertionError("the Method path never triggers"); }
        @Override public Sample sample(String nodeId) {
            sampled.add(nodeId);
            return new Sample(42.0, good, clock.now.minusMillis(ageMs));
        }
        @Override public MethodResult method(String objectNodeId, String methodNodeId, double input) throws Exception {
            calls++;
            if (methodOk == null) throw new PlantUnreachableException("session lost mid-call");
            return methodOk ? new MethodResult(true, String.valueOf(input), "called " + methodNodeId + "(" + input + ")")
                    : new MethodResult(false, null, "Bad_OutOfRange");
        }
    }

    @TempDir Path tmp;
    Path registry, ledgerDir, operatorKey;
    final Map<String, KeyPair> keys = new LinkedHashMap<>();
    final MovableClock clock = new MovableClock();
    FakePlant plant;
    CommandPolicy policy;

    @BeforeEach void setup() throws Exception {
        Path bundle = tmp.resolve("bundle");
        Path fixture = Path.of("../core/src/test/resources/mapping-fixtures/vor-read");
        try (var walk = Files.walk(fixture)) {
            for (Path p : walk.toList()) {
                Path q = bundle.resolve(fixture.relativize(p).toString());
                if (Files.isDirectory(p)) Files.createDirectories(q); else Files.copy(p, q);
            }
        }
        registry = tmp.resolve("registry");
        Files.createDirectories(registry.resolve("identity"));
        StringBuilder lines = new StringBuilder();
        for (String who : List.of("proposer", "approver", "agent", "operator", "other")) {
            KeyPair kp = Ed25519Keys.generate();
            keys.put(who, kp);
            Files.writeString(tmp.resolve(who + ".key"), Ed25519Keys.privateKeyB64(kp.getPrivate()));
            lines.append(JSON.writeValueAsString(new AuthorizedKey(who, Ed25519Keys.publicKeyB64(kp.getPublic())))).append('\n');
        }
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"), lines);
        grants(true);
        var service = new MappingRegistry(registry, clock, () -> {});
        service.approve(bundle, "approval-1", "proposer", tmp.resolve("proposer.key"), "approver", tmp.resolve("approver.key"));
        service.publish(bundle, "vor-read", "1.0.0", "approval-1", new MappingRegistry.HeadSigners("proposer",
                tmp.resolve("proposer.key"), "approver", tmp.resolve("approver.key"), Duration.ofDays(90)));
        policy = AclMapperFactory.create().readValue("{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"set-temperature\","
                + "\"principal\":\"agent\",\"target\":{\"group\":\"" + GROUP + "\",\"edge\":\"" + EDGE + "\",\"device\":\"Line1/Mixer1\"},"
                + "\"command\":\"" + METHOD + "\",\"constraint\":{\"type\":\"Double\",\"min\":0.0,\"max\":100.0}}]}", CommandPolicy.class);
        ledgerDir = tmp.resolve("ledger");
        plant = new FakePlant(clock);
    }

    void grants(boolean operatorMayCoSign) throws Exception {
        List<String> rules = new ArrayList<>(List.of(
                "{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"line1\"}",
                "{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"line1\"}",
                "{\"id\":\"agent-proposes\",\"principal\":\"agent\",\"action\":\"propose_command\",\"target\":\"command\",\"kind\":\"method\",\"ref\":\"line1\"}"));
        if (operatorMayCoSign) {
            rules.add("{\"id\":\"operator-co-signs\",\"principal\":\"operator\",\"action\":\"approve_command\",\"target\":\"command\",\"kind\":\"method\",\"ref\":\"line1\"}");
        }
        Files.writeString(registry.resolve("identity/activation-policy.json"),
                "{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[" + String.join(",", rules) + "]}");
    }

    NcmdOpcUaBridge bridge(boolean logOnly, CommandLedger ledger) {
        return new NcmdOpcUaBridge(GROUP, EDGE, policy, plant, null, null, null, logOnly, new EdgeHealth(), 1, 8,
                false, 16, null, ledger, false, new NcmdOpcUaBridge.MethodPath(registry, new OpaMethodAuthorizer(), clock));
    }
    NcmdOpcUaBridge bridge() { return bridge(false, new CommandLedger(ledgerDir, clock)); }

    /** An agent-signed statement as vor-propose writes it; {@code coSign} adds the operator's signature over the same bytes. */
    JsonNode envelope(double value, boolean coSign, Consumer<ObjectNode> edit) throws Exception {
        byte[] headBytes = Files.readAllBytes(registry.resolve("mappings/heads/line1.json"));
        JsonNode head = JSON.readTree(headBytes);
        ObjectNode answer = object();
        answer.putObject("answer").putObject("pin").put("stream_id", "line1").put("release_id", text(head, "id"))
                .put("version", text(head, "version")).put("release_sha256", text(head, "sha256"))
                .put("file", "payload/mappings/0.json").put("field_id", "temp");
        answer.putObject("verdict").put("usable", true);
        byte[] evidence = JSON.writeValueAsBytes(answer);
        ObjectNode s = object().put("_type", CommandProposal.STATEMENT);
        ArrayNode sub = s.putArray("subject");
        sub.add(object().put("name", "heads/line1.json").set("digest", object().put("sha256", sha(headBytes))));
        sub.add(object().put("name", "releases/vor-read/1.0.0/release.json").set("digest", object().put("sha256", text(head, "sha256"))));
        sub.add(object().put("name", "evidence").set("digest", object().put("sha256", sha(evidence))));
        s.put("predicateType", CommandProposal.PREDICATE);
        ObjectNode p = s.putObject("predicate");
        p.put("cmdId", UUID.randomUUID().toString()).put("streamId", "line1");
        p.putObject("target").put("group", GROUP).put("edge", EDGE).put("device", "Line1/Mixer1");
        ObjectNode m = p.putObject("method");
        m.put("objectNodeId", OBJECT).put("methodNodeId", METHOD);
        m.putArray("inputs").addObject().put("name", "targetTemperature").put("type", "Double").put("value", value);
        p.putObject("validity").put("notBefore", clock.now.minusSeconds(60).toString()).put("notAfter", clock.now.plusSeconds(600).toString());
        p.put("proposedBy", "agent").put("approvedBy", "operator");
        p.putObject("evidence").put("mediaType", "application/json").put("base64", Base64.getEncoder().encodeToString(evidence));
        edit.accept(p);
        byte[] payload = JSON.writeValueAsBytes(s);
        byte[] pae = Dsse.pae(Dsse.IN_TOTO, payload);
        List<Dsse.Signature> sigs = new ArrayList<>(List.of(new Dsse.Signature("agent", Ed25519Keys.sign(pae, keys.get("agent").getPrivate()))));
        if (coSign) sigs.add(new Dsse.Signature("operator", Ed25519Keys.sign(pae, keys.get("operator").getPrivate())));
        return Dsse.envelope(Dsse.IN_TOTO, payload, sigs);
    }
    JsonNode approved(double value) throws Exception { return envelope(value, true, p -> {}); }
    static String cmdId(JsonNode env) throws Exception {
        return text(JSON.readTree(Base64.getDecoder().decode(text(env, "payload"))).path("predicate"), "cmdId");
    }

    static SparkplugBPayload ncmd(JsonNode env, String metric, String op) throws Exception {
        var props = new PropertySetBuilder().addProperty("op", new PropertyValue(PropertyDataType.String, op)).createPropertySet();
        return new SparkplugBPayloadBuilder().setUuid(cmdId(env)).setTimestamp(new Date())
                .addMetric(new MetricBuilder(metric, MetricDataType.String, JSON.writeValueAsString(env)).properties(props).createMetric())
                .createPayload();
    }
    static SparkplugBPayload ncmd(JsonNode env) throws Exception { return ncmd(env, NcmdOpcUaBridge.METHOD_METRIC, "method"); }

    static void refused(NcmdResponse r, String code) {
        assertFalse(r.ok(), r.detail());
        assertTrue(r.detail().startsWith("denied: " + code), "expected " + code + ", got: " + r.detail());
    }
    List<CommandLedgerEntry> entries() throws Exception { return new CommandLedger(ledgerDir, clock).readCurrent(GROUP, EDGE); }

    @Test void anApprovedProposalIsCalledOnceAndItsReservationOutlivesTheBridge() throws Exception {
        JsonNode env = approved(42.0);
        NcmdResponse r = bridge().handle(NCMD, ncmd(env));
        assertTrue(r.ok(), r.detail());
        assertEquals(cmdId(env), r.cmdId(), "the answer correlates by the proposal's cmdId");
        assertEquals("42.0", r.value());
        assertEquals(1, plant.calls);
        assertEquals(List.of(TEMP), plant.sampled, "the precondition is the release's source for the evidence field");
        List<CommandLedgerEntry> e = entries();
        assertEquals(2, e.size());
        assertEquals("reserved", e.get(0).event().outcome());
        assertEquals("applied", e.get(1).event().outcome());
        assertEquals("agent", e.get(0).event().subject());

        refused(bridge().handle(NCMD, ncmd(env)), "command.replay");
        refused(bridge().handle(NCMD, ncmd(env)), "command.replay");
        assertEquals(1, plant.calls, "a reserved cmdId is never called again, by this bridge or a new one");
    }

    @Test void refusalsBeforeTheReservationLeaveTheCmdIdFree() throws Exception {
        JsonNode env = approved(42.0);
        NcmdOpcUaBridge b = bridge();
        refused(b.handle("bifrost/" + GROUP + "/QUERY/" + EDGE, ncmd(env)), "command.malformed");
        refused(b.handle(NCMD, ncmd(env, NcmdOpcUaBridge.METHOD_METRIC, "write")), "command.malformed");
        SparkplugBPayload two = ncmd(env);
        two.addMetric(new MetricBuilder("extra", MetricDataType.String, "x").createMetric());
        refused(b.handle(NCMD, two), "command.malformed");
        refused(b.handle(NCMD, ncmd(envelope(42.0, false, p -> {}))), "command.signature");
        refused(b.handle(NCMD, ncmd(envelope(42.0, true, p -> ((ObjectNode) p.get("target")).put("edge", "other-edge")))), "command.malformed");
        plant.good = false;
        refused(b.handle(NCMD, ncmd(env)), "command.precondition");
        plant.good = true;
        plant.ageMs = 5001;
        refused(b.handle(NCMD, ncmd(env)), "command.precondition");
        plant.ageMs = 1000;
        clock.now = clock.now.plusSeconds(600);
        refused(b.handle(NCMD, ncmd(env)), "command.window");
        clock.now = clock.now.minusSeconds(600);
        assertEquals(0, plant.calls);
        assertTrue(entries().stream().allMatch(x -> "denied".equals(x.event().outcome())), "every refusal is an audit entry, none a reservation");

        assertTrue(b.handle(NCMD, ncmd(env)).ok(), "the same cmdId still executes: nothing above consumed it");
        assertEquals(1, plant.calls);
    }

    @Test void bothPoliciesMustAllow() throws Exception {
        refused(bridge().handle(NCMD, ncmd(approved(150.0))), "command.policy.denied");
        grants(false);
        NcmdResponse r = bridge().handle(NCMD, ncmd(approved(42.0)));
        refused(r, "command.opa.denied");
        assertTrue(r.detail().contains("grant.approve"), r.detail());
        assertEquals(0, plant.calls);
    }

    @Test void logOnlyDoesNotApplyToTheMethodPath() throws Exception {
        refused(bridge(true, new CommandLedger(ledgerDir, clock)).handle(NCMD, ncmd(approved(150.0))), "command.policy.denied");
        assertEquals(0, plant.calls, "a would-deny on the Method path is a deny");
    }

    @Test void theLedgerIsRequired() throws Exception {
        refused(bridge(false, null).handle(NCMD, ncmd(approved(42.0))), "command.ledger.required");
        // A regular file where the edge's segment directory must be: the reservation cannot be written.
        Files.createDirectories(ledgerDir.resolve("commands/Bifrost-Line1"));
        Files.writeString(ledgerDir.resolve("commands/Bifrost-Line1/recipe-edge"), "not a directory");
        refused(bridge().handle(NCMD, ncmd(approved(42.0))), "command.ledger.required");
        assertEquals(0, plant.calls);
    }

    @Test void aFailedOrUnconfirmedCallStillConsumesTheCmdId() throws Exception {
        plant.methodOk = false;
        JsonNode failed = approved(42.0);
        NcmdResponse r = bridge().handle(NCMD, ncmd(failed));
        assertFalse(r.ok());
        assertTrue(r.detail().startsWith("failed: command.method.failed (method-failed)"), r.detail());
        plant.methodOk = null;
        JsonNode lost = approved(43.0);
        assertTrue(bridge().handle(NCMD, ncmd(lost)).detail().startsWith("failed: command.method.failed (unknown)"));
        plant.methodOk = true;
        refused(bridge().handle(NCMD, ncmd(failed)), "command.replay");
        refused(bridge().handle(NCMD, ncmd(lost)), "command.replay");
        assertEquals(2, plant.calls, "never retried: a new attempt needs a new proposal");
        assertEquals(List.of("reserved", "method-failed", "reserved", "unknown", "denied", "denied"),
                entries().stream().map(x -> x.event().outcome()).toList());
    }
}
