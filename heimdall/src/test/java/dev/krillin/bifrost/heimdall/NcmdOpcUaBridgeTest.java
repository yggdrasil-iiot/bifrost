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
import org.junit.jupiter.api.io.TempDir;

import java.security.KeyPair;
import java.security.PublicKey;

import dev.krillin.bifrost.core.acl.AclMapperFactory;
import dev.krillin.bifrost.core.acl.CommandEnvelope;
import dev.krillin.bifrost.core.command.CommandChain;
import dev.krillin.bifrost.core.command.CommandLedger;
import dev.krillin.bifrost.core.command.CommandLedgerEntry;
import dev.krillin.bifrost.core.acl.CommandPolicy;
import dev.krillin.bifrost.core.acl.Constraint;
import dev.krillin.bifrost.core.acl.Rule;
import dev.krillin.bifrost.core.acl.Target;
import dev.krillin.bifrost.core.conformance.ConformancePolicy;
import dev.krillin.bifrost.core.identity.Ed25519Keys;
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

    @Test void above_max_denied_by_conformance_not_applied() throws Exception {
        // Post-migration: authz allows a type-ok Rpm=9999 (range left policy.json); ② envelope (governed
        // Mixer model Rpm∈[0,3000]) denies it. The Mixer conformance policy has NO cross-constraints, so
        // no sibling is read — Boolean Running/Secret are never readDouble'd.
        UdtDefinition mixerDef = new UdtDefinition("Line1-Mixer", SemVer.parse("1.0.0"),
                List.of(new Member("Rpm", "Double", null, new Range(0, 3000)),
                        new Member("Temp", "Double", null, new Range(0, 450))),
                List.of(), null);
        ConformancePolicy mixerPolicy = new ConformancePolicy("Line1-Mixer-policy", "1.0.0",
                "Line1-Mixer", "1.0.0", new ConformancePolicy.Dial("envelope", null, null, null),
                List.of(), List.of(new NodeBinding("ns=2;s=Recipe/Rpm", null, "Rpm")));
        FakeApplier fake = new FakeApplier();
        NcmdResponse r = new NcmdOpcUaBridge(GROUP, EDGE, policy(), fake, mixerDef, mixerPolicy, null)
                .handle(NCMD_TOPIC, cmd("c-2", "write", "ns=2;s=Recipe/Rpm", 9999.0, MetricDataType.Double, null, null));
        assertFalse(fake.writeCalled, "an above-max write must NOT reach the applier (② envelope)");
        assertFalse(r.ok());
        assertTrue(r.detail().contains("above-max"), r.detail());
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

    // ----- R2: the command ledger -----

    private CommandLedger ledgerAt(java.nio.file.Path dir) {
        return new CommandLedger(dir, java.time.Clock.systemUTC());
    }

    private NcmdOpcUaBridge recording(Applier applier, CommandLedger ledger, boolean logOnly,
                                      boolean requireLedger) throws Exception {
        return new NcmdOpcUaBridge(GROUP, EDGE, policy(), applier, null, null, null, logOnly,
                new EdgeHealth(), 4, 64, false, 64, null, ledger, requireLedger);
    }

    private java.util.List<CommandLedgerEntry> entries(CommandLedger l) throws Exception {
        return l.readCurrent(GROUP, EDGE);
    }

    @Test void an_applied_command_leaves_intent_then_outcome(@TempDir java.nio.file.Path dir) throws Exception {
        CommandLedger l = ledgerAt(dir);
        NcmdResponse r = recording(new FakeApplier(), l, false, false).handle(NCMD_TOPIC,
                cmd("l-1", "write", "ns=2;s=Recipe/Rpm", 1500.0, MetricDataType.Double, null, null));
        assertTrue(r.ok());
        var es = entries(l);
        assertEquals(2, es.size(), "an applied command is two facts, not one");
        assertEquals("intent", es.get(0).event().phase());
        assertEquals("pending", es.get(0).event().outcome());
        assertEquals("outcome", es.get(1).event().phase());
        assertEquals("applied", es.get(1).event().outcome());
        assertTrue(CommandChain.verify(es, CommandChain.GENESIS).intact());
    }

    @Test void a_denied_command_leaves_one_entry(@TempDir java.nio.file.Path dir) throws Exception {
        CommandLedger l = ledgerAt(dir);
        NcmdResponse r = recording(new FakeApplier(), l, false, false).handle(NCMD_TOPIC,
                cmd("l-2", "write", "ns=2;s=Nope", 1.0, MetricDataType.Double, null, null));
        assertFalse(r.ok());
        var es = entries(l);
        assertEquals(1, es.size(), "a refusal never reaches the applier, so there is no outcome");
        assertEquals("denied", es.get(0).event().outcome());
    }

    /**
     * Log-only makes a command BOTH would-denied and applied — they are not alternatives. Two
     * entries carry both facts, which is what actually happened.
     */
    @Test void a_log_only_shadowed_command_records_the_reason_and_the_apply(@TempDir java.nio.file.Path dir)
            throws Exception {
        CommandLedger l = ledgerAt(dir);
        FakeApplier fake = new FakeApplier();
        NcmdResponse r = recording(fake, l, true, false).handle(NCMD_TOPIC,
                cmd("l-3", "write", "ns=2;s=Nope", 1.0, MetricDataType.Double, null, null));
        assertTrue(r.ok(), "log-only applies what it would have denied");
        assertTrue(fake.writeCalled);
        var es = entries(l);
        assertEquals(2, es.size());
        assertEquals("intent", es.get(0).event().phase());
        assertNotNull(es.get(0).event().reason(), "the intent must carry the would-deny reason");
        assertEquals("applied", es.get(1).event().outcome());
    }

    /**
     * THE guarantee this round buys: with the bar on, a command whose intent cannot be recorded is
     * refused and the plant is never touched. The applier must not have been called.
     */
    @Test void an_unwritable_ledger_refuses_before_the_applier(@TempDir java.nio.file.Path dir) throws Exception {
        // Occupy the directory path the segment needs with a regular file, so createDirectories
        // fails on every platform - chmod on a directory does not reliably deny a JVM on Windows.
        java.nio.file.Path blocked = dir.resolve("blocked");
        java.nio.file.Files.writeString(blocked, "not a directory");
        CommandLedger l = new CommandLedger(blocked, java.time.Clock.systemUTC());
        FakeApplier fake = new FakeApplier();
        NcmdResponse r = recording(fake, l, false, true).handle(NCMD_TOPIC,
                cmd("l-4", "write", "ns=2;s=Recipe/Rpm", 1500.0, MetricDataType.Double, null, null));
        assertFalse(r.ok());
        assertTrue(r.detail().contains("command.ledger.unwritable"), r.detail());
        assertFalse(fake.writeCalled, "the plant was touched without a record");
    }

    /** Same reasoning as R1's bar: log-only inverts verdicts, and this is not a verdict. */
    @Test void an_unwritable_ledger_plus_log_only_still_refuses(@TempDir java.nio.file.Path dir) throws Exception {
        java.nio.file.Path blocked = dir.resolve("blocked");
        java.nio.file.Files.writeString(blocked, "not a directory");
        FakeApplier fake = new FakeApplier();
        NcmdResponse r = recording(fake, new CommandLedger(blocked, java.time.Clock.systemUTC()), true, true)
                .handle(NCMD_TOPIC,
                        cmd("l-5", "write", "ns=2;s=Recipe/Rpm", 1500.0, MetricDataType.Double, null, null));
        assertFalse(r.ok(), "log-only must not shadow an unwritable ledger: " + r.detail());
        assertFalse(fake.writeCalled);
    }

    /** Bar off: the same unwritable ledger applies the command, proving the refusal is the bar's. */
    @Test void an_unwritable_ledger_with_the_bar_off_still_applies(@TempDir java.nio.file.Path dir)
            throws Exception {
        java.nio.file.Path blocked = dir.resolve("blocked");
        java.nio.file.Files.writeString(blocked, "not a directory");
        FakeApplier fake = new FakeApplier();
        NcmdResponse r = recording(fake, new CommandLedger(blocked, java.time.Clock.systemUTC()), false, false)
                .handle(NCMD_TOPIC,
                        cmd("l-6", "write", "ns=2;s=Recipe/Rpm", 1500.0, MetricDataType.Double, null, null));
        assertTrue(r.ok(), r.detail());
        assertTrue(fake.writeCalled);
    }

    /** No ledger configured is the pre-R2 path, byte for byte. */
    @Test void no_ledger_configured_changes_nothing() throws Exception {
        FakeApplier fake = new FakeApplier();
        NcmdResponse r = bridge(fake).handle(NCMD_TOPIC,
                cmd("l-7", "write", "ns=2;s=Recipe/Rpm", 1500.0, MetricDataType.Double, null, null));
        assertTrue(r.ok());
        assertTrue(fake.writeCalled);
    }

    // ----- R1: the signature bar -----

    private static final String P = "recipe-writer";

    /** A payload carrying sub/sig metric properties, signed over the canonical preimage. */
    private SparkplugBPayload signedCmd(String cmdId, String node, Object value, String subject,
                                        java.security.PrivateKey key) throws Exception {
        String sig = CommandEnvelope.sign(GROUP, EDGE, cmdId, node, value, "Double", key);
        PropertySetBuilder pb = new PropertySetBuilder()
                .addProperty("op", new PropertyValue(PropertyDataType.String, "write"))
                .addProperty("sub", new PropertyValue(PropertyDataType.String, subject))
                .addProperty("sig", new PropertyValue(PropertyDataType.String, sig));
        return new SparkplugBPayloadBuilder().setUuid(cmdId).setTimestamp(new Date())
                .addMetric(new MetricBuilder(node, MetricDataType.Double, value)
                        .properties(pb.createPropertySet()).createMetric())
                .createPayload();
    }

    /** Bar ON, with a one-principal trust anchor. */
    private NcmdOpcUaBridge barred(Applier applier, String principal, PublicKey pk) throws Exception {
        return new NcmdOpcUaBridge(GROUP, EDGE, policy(), applier, null, null, null, false,
                new EdgeHealth(), 4, 64, true, 64, name -> principal.equals(name) ? pk : null);
    }

    @Test void bar_on_a_correctly_signed_command_is_applied() throws Exception {
        KeyPair kp = Ed25519Keys.generate();
        FakeApplier fake = new FakeApplier();
        NcmdResponse r = barred(fake, P, kp.getPublic())
                .handle(NCMD_TOPIC, signedCmd("s-1", "ns=2;s=Recipe/Rpm", 1500.0, P, kp.getPrivate()));
        assertTrue(r.ok(), r.detail());
        assertTrue(fake.writeCalled);
    }

    @Test void bar_on_an_unsigned_command_is_refused() throws Exception {
        FakeApplier fake = new FakeApplier();
        NcmdResponse r = barred(fake, P, Ed25519Keys.generate().getPublic())
                .handle(NCMD_TOPIC, cmd("s-2", "write", "ns=2;s=Recipe/Rpm", 1500.0, MetricDataType.Double, null, null));
        assertFalse(r.ok());
        assertTrue(r.detail().contains("command.unsigned"), r.detail());
        assertFalse(fake.writeCalled, "an unsigned command must not reach the applier");
    }

    @Test void bar_on_a_bad_signature_is_refused() throws Exception {
        KeyPair kp = Ed25519Keys.generate();
        FakeApplier fake = new FakeApplier();
        // Signed over 1500, submitted as 9999.
        String sig = CommandEnvelope.sign(GROUP, EDGE, "s-3", "ns=2;s=Recipe/Rpm", 1500.0, "Double", kp.getPrivate());
        PropertySetBuilder pb = new PropertySetBuilder()
                .addProperty("op", new PropertyValue(PropertyDataType.String, "write"))
                .addProperty("sub", new PropertyValue(PropertyDataType.String, P))
                .addProperty("sig", new PropertyValue(PropertyDataType.String, sig));
        SparkplugBPayload tampered = new SparkplugBPayloadBuilder().setUuid("s-3").setTimestamp(new Date())
                .addMetric(new MetricBuilder("ns=2;s=Recipe/Rpm", MetricDataType.Double, 9999.0)
                        .properties(pb.createPropertySet()).createMetric())
                .createPayload();
        NcmdResponse r = barred(fake, P, kp.getPublic()).handle(NCMD_TOPIC, tampered);
        assertFalse(r.ok());
        assertTrue(r.detail().contains("command.sig.invalid"), r.detail());
        assertFalse(fake.writeCalled);
    }

    @Test void bar_on_an_unknown_principal_is_refused() throws Exception {
        KeyPair kp = Ed25519Keys.generate();
        FakeApplier fake = new FakeApplier();
        NcmdResponse r = barred(fake, P, kp.getPublic())
                .handle(NCMD_TOPIC, signedCmd("s-4", "ns=2;s=Recipe/Rpm", 1500.0, "nobody", kp.getPrivate()));
        assertFalse(r.ok());
        assertTrue(r.detail().contains("command.principal.unknown"), r.detail());
    }

    @Test void bar_on_a_replayed_cmdId_is_refused() throws Exception {
        KeyPair kp = Ed25519Keys.generate();
        FakeApplier fake = new FakeApplier();
        NcmdOpcUaBridge b = barred(fake, P, kp.getPublic());
        SparkplugBPayload once = signedCmd("s-5", "ns=2;s=Recipe/Rpm", 1500.0, P, kp.getPrivate());
        assertTrue(b.handle(NCMD_TOPIC, once).ok());
        NcmdResponse again = b.handle(NCMD_TOPIC, once);
        assertFalse(again.ok());
        assertTrue(again.detail().contains("command.replay"), again.detail());
    }

    /** A null cmdId leaves nothing for a signature to bind, so it is itself a refusal. */
    @Test void bar_on_a_missing_cmdId_is_refused() throws Exception {
        KeyPair kp = Ed25519Keys.generate();
        NcmdResponse r = barred(new FakeApplier(), P, kp.getPublic())
                .handle(NCMD_TOPIC, signedCmd(null, "ns=2;s=Recipe/Rpm", 1500.0, P, kp.getPrivate()));
        assertFalse(r.ok());
        assertTrue(r.detail().contains("command.unsigned"), r.detail());
    }

    /**
     * THE decision-(a) test. {@code refuse()} returns null under log-only and its caller falls
     * through and applies. If the signature refusals went through it, an unsigned command with both
     * flags on would be logged would-deny and then APPLIED, reaching authorize() with a null subject
     * that skips the principal check. The bar is an authentication question, not a policy verdict,
     * and log-only inverts verdicts.
     */
    @Test void bar_on_plus_log_only_still_refuses_an_unsigned_command() throws Exception {
        FakeApplier fake = new FakeApplier();
        PublicKey pk = Ed25519Keys.generate().getPublic();
        NcmdOpcUaBridge logOnlyBarred = new NcmdOpcUaBridge(GROUP, EDGE, policy(), fake, null, null, null,
                true, new EdgeHealth(), 4, 64, true, 64, name -> P.equals(name) ? pk : null);
        NcmdResponse r = logOnlyBarred.handle(NCMD_TOPIC,
                cmd("s-6", "write", "ns=2;s=Recipe/Rpm", 1500.0, MetricDataType.Double, null, null));
        assertFalse(r.ok(), "log-only must not shadow the signature bar: " + r.detail());
        assertTrue(r.detail().contains("command.unsigned"), r.detail());
        assertFalse(fake.writeCalled, "log-only applied an unsigned command");
    }

    /** Bar OFF is the pre-R1 path — which is what keeps the seven existing NCMD gates meaningful. */
    @Test void bar_off_an_unsigned_command_is_applied_as_before() throws Exception {
        FakeApplier fake = new FakeApplier();
        NcmdResponse r = bridge(fake).handle(NCMD_TOPIC,
                cmd("s-7", "write", "ns=2;s=Recipe/Rpm", 1500.0, MetricDataType.Double, null, null));
        assertTrue(r.ok(), r.detail());
        assertTrue(fake.writeCalled);
    }

    // ----- R0: an unreachable plant is a refusal, but never a verdict -----

    @Test void unreachable_plant_on_the_apply_path_is_not_reported_as_a_denial() throws Exception {
        FakeApplier fake = new FakeApplier();
        fake.writeUnreachable = true;
        // Rpm=1500 is ALLOWED by registry/policy.json, so any refusal here is about reachability.
        NcmdResponse r = bridge(fake).handle(NCMD_TOPIC,
                cmd("u-1", "write", "ns=2;s=Recipe/Rpm", 1500.0, MetricDataType.Double, null, null));

        assertFalse(r.ok(), "the edge must not claim success for a write it could not make");
        assertTrue(r.detail().contains("plant-unreachable"), r.detail());
        assertFalse(r.detail().contains("denied:"), "not a policy denial: " + r.detail());
    }

    @Test void unreachable_plant_on_the_conformance_path_is_not_reported_as_conformance_error()
            throws Exception {
        FakeApplier fake = new FakeApplier();
        fake.readDoubleUnreachable = true;   // the cross-member sibling read is what fails
        NcmdResponse r = weldBridge(fake).handle(NCMD_TOPIC,
                cmd("u-2", "write", WELD_NODE, 5.0, MetricDataType.Double, null, null));

        assertFalse(r.ok());
        assertTrue(r.detail().contains("plant-unreachable"), r.detail());
        assertFalse(r.detail().contains("conformance-error"),
                "an outage must not send the operator to look at the model: " + r.detail());
    }

    // ----- R0: dispatch and counters -----

    @Test void overload_refusal_is_a_refusal_and_says_why() {
        NcmdResponse r = NcmdOpcUaBridge.overloaded("c-9");
        assertFalse(r.ok(), "an overloaded edge must not report success for a command it never ran");
        assertEquals("c-9", r.cmdId(), "the refusal must correlate, or the caller cannot match it");
        assertTrue(r.detail().contains("overloaded"), r.detail());
    }

    @Test void counters_separate_applied_from_denied() throws Exception {
        EdgeHealth h = new EdgeHealth();
        NcmdOpcUaBridge b = new NcmdOpcUaBridge(GROUP, EDGE, policy(), new FakeApplier(),
                null, null, null, false, h, 4, 64);
        b.handle(NCMD_TOPIC, cmd("c-1", "write", "ns=2;s=Recipe/Rpm", 1500.0, MetricDataType.Double, null, null));
        b.handle(NCMD_TOPIC, cmd("c-2", "write", "ns=2;s=Nope", 1.0, MetricDataType.Double, null, null));
        assertEquals(1, h.appliedCount());
        assertEquals(1, h.deniedCount());
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
        // The two below are a DIFFERENT failure from the one above: not a bad read, but no visible
        // plant at all. The bridge must tell them apart, which is what R0's unreachable tests assert.
        boolean readDoubleUnreachable;
        boolean writeUnreachable;
        Result writeResult = new Result(true, "written+confirmed");
        Result callResult = new Result(true, "rising-edge confirmed");
        ReadBack readResult = new ReadBack("1500.0", true);

        @Override public ReadBack read(String nodeId) {
            readCalled = true;
            return readResult;
        }
        @Override public double readDouble(String nodeId) throws Exception {
            lastReadDoubleNode = nodeId;
            if (readDoubleUnreachable) {
                throw new PlantUnreachableException("session closed");
            }
            if (nodeId.equals(throwOnReadDoubleNode)) {
                throw new Exception("readDouble bad quality " + nodeId);
            }
            return readDoubleResult;
        }
        @Override public Result write(String nodeId, double value) throws Exception {
            if (writeUnreachable) {
                throw new PlantUnreachableException("session closed");
            }
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
