package dev.krillin.bifrost.heimdall;

import java.nio.file.Path;
import java.util.function.Function;

import com.fasterxml.jackson.databind.ObjectMapper;

import dev.krillin.bifrost.core.acl.AclMapperFactory;
import dev.krillin.bifrost.core.acl.CommandPolicy;
import dev.krillin.bifrost.core.conformance.ConformancePolicy;
import dev.krillin.bifrost.core.conformance.MasterSpecStore;
import dev.krillin.bifrost.core.schema.DefinitionStore;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import dev.krillin.bifrost.core.schema.MasterSpec;
import dev.krillin.bifrost.core.schema.UdtDefinition;

/**
 * Runnable self-bridge. Wires the broker, the OPC-UA endpoint, the Sparkplug identity, and the edge
 * policy from env/args (with demo defaults), then connects and prints {@code [BRIDGE] ready} — the
 * line the Chunk-3 gate waits on.
 *
 * <pre>
 *   MQTT_URL     tcp://localhost:1883            (broker)
 *   OPCUA_URL    opc.tcp://localhost:48400       (OPC-UA server / sim)
 *   SPB_GROUP    Bifrost:Line1
 *   SPB_EDGE     recipe-edge
 *   POLICY_PATH  registry/policy.json
 * </pre>
 *
 * Run: {@code mvn -q compile exec:java -Dexec.mainClass=dev.krillin.bifrost.heimdall.NcmdOpcUaBridgeMain}
 */
public final class NcmdOpcUaBridgeMain {

    /**
     * Resolved runtime configuration — a testable seam around the env lookups below.
     * {@code requireSignedActivation} (env {@code REQUIRE_SIGNED_ACTIVATION}, default OFF) selects the
     * edge's ledger-trust check: off → T4 structural chain (verifyChain); on → full
     * {@link dev.krillin.bifrost.core.identity.SignedLedgerVerifier} (structural + dual-sig + signed head).
     */
    record Config(String broker, String opcua, String group, String edge, String policyPath,
                  String registryPath, String conformancePath, String activationPath, String activationTarget,
                  boolean requireSignedActivation) {}

    static Config resolve(Function<String, String> getenv) {
        String broker = env(getenv, "MQTT_URL", "tcp://localhost:1883");
        String opcua = env(getenv, "OPCUA_URL", "opc.tcp://localhost:48400");
        String group = env(getenv, "SPB_GROUP", "Bifrost:Line1");
        String edge = env(getenv, "SPB_EDGE", "recipe-edge");
        String policyPath = env(getenv, "POLICY_PATH", "registry/policy.json");
        String registryPath = env(getenv, "REGISTRY_PATH", "registry");
        String conformancePath = env(getenv, "CONFORMANCE_PATH", null);
        String activationPath = env(getenv, "ACTIVATION_PATH", null);
        String activationTarget = env(getenv, "ACTIVATION_TARGET", null);
        // NB: Boolean.parseBoolean("on") is FALSE — accept on/1/true so the gate's =on and =true both work.
        String rsa = env(getenv, "REQUIRE_SIGNED_ACTIVATION", "false").strip();
        boolean requireSigned = "true".equalsIgnoreCase(rsa) || "on".equalsIgnoreCase(rsa) || "1".equals(rsa);
        boolean rsaOff = "false".equalsIgnoreCase(rsa) || "off".equalsIgnoreCase(rsa) || "0".equals(rsa) || rsa.isEmpty();
        if (!requireSigned && !rsaOff)   // an unrecognized non-empty value fails to OFF — say so loudly, don't silently downgrade
            System.err.println("[BRIDGE] WARN: REQUIRE_SIGNED_ACTIVATION='" + rsa
                    + "' not recognized — treating as OFF (structural-only). Use true/on/1 or false/off/0.");
        return new Config(broker, opcua, group, edge, policyPath, registryPath, conformancePath, activationPath,
                activationTarget, requireSigned);
    }

    /**
     * The optionally-loaded conformance trio. When {@code conformancePath} is null/blank all three are
     * null and the bridge runs pure-authz (② off), exactly as before this feature existed.
     */
    record Conformance(UdtDefinition def, ConformancePolicy policy, MasterSpec recipe) {
        static final Conformance OFF = new Conformance(null, null, null);
    }

    /**
     * Loads the governed {@link ConformancePolicy} from {@code conformancePath}, resolves its equipment
     * {@link UdtDefinition} from the registry, and (recipe-mode only) the active {@link MasterSpec}.
     * Returns {@link Conformance#OFF} when {@code conformancePath} is null/blank.
     */
    static Conformance loadConformance(Config config) throws Exception {
        if (config.conformancePath() == null || config.conformancePath().isBlank()) {
            return Conformance.OFF;
        }
        ObjectMapper cmapper = JsonMapperFactory.create();
        ConformancePolicy cp = cmapper.readValue(Path.of(config.conformancePath()).toFile(), ConformancePolicy.class);
        Path registryDir = Path.of(config.registryPath());
        UdtDefinition cdef = new DefinitionStore(registryDir)
                .load(cp.equipmentRef(), cp.equipmentVersion())
                .orElseThrow(() -> new IllegalStateException("conformance equipment def not in registry: "
                        + cp.equipmentRef() + "@" + cp.equipmentVersion()));
        MasterSpec recipe = null;
        if (cp.dial() != null && "recipe".equals(cp.dial().mode())) {
            String ref = cp.dial().activeRecipeRef();
            if (config.activationTarget() != null && !config.activationTarget().isBlank()) {
                // governed activation: the ledger's active pointer (not the dial) picks the version; verify-then-trust.
                java.nio.file.Path ledgerDir = (config.activationPath() != null && !config.activationPath().isBlank())
                        ? java.nio.file.Path.of(config.activationPath()) : registryDir;
                dev.krillin.bifrost.core.activation.ActivationLedger ledger =
                        new dev.krillin.bifrost.core.activation.ActivationLedger(ledgerDir);
                assertLedgerTrustworthy(ledgerDir, config.activationTarget(), config.requireSignedActivation());
                var active = ledger
                        .active(config.activationTarget(), "recipe", ref)
                        .orElseThrow(() -> new IllegalStateException("activation.edge.no-active-pointer: no active recipe for target "
                                + config.activationTarget() + " ref " + ref));
                // kind is "recipe" here because this bind path is recipe-only; the gate authorizes the same
                // (target, "recipe", ref) tuple, so a legitimate activation admitted at the gate is not spuriously
                // denied at the edge. (A non-recipe activation never reaches this bind — it fails at no-active-pointer.)
                assertActivationAuthorized(ledgerDir, config.activationTarget(), "recipe", ref,
                        active.activatedBy(), active.approvedBy(), config.requireSignedActivation());
                java.nio.file.Path specFile = new MasterSpecStore().file(registryDir, ref, active.version());
                if (!java.nio.file.Files.isRegularFile(specFile))
                    throw new IllegalStateException("activation.edge.artifact-missing: " + specFile);
                byte[] bytes = java.nio.file.Files.readAllBytes(specFile);      // verify BEFORE parse
                String sha = dev.krillin.bifrost.core.activation.Sha256.hex(bytes);
                if (!sha.equals(active.contentSha256()))
                    throw new IllegalStateException("activation.edge.content-mismatch: ref " + ref + "@" + active.version()
                            + " edge sha " + sha + " != approved " + active.contentSha256());
                recipe = cmapper.readValue(bytes, MasterSpec.class);
                System.out.println("[BRIDGE] activation bound " + ref + "@" + active.version()
                        + " (approved by " + active.approvedBy() + ", sha256 " + sha + ")");
            } else {
                recipe = new MasterSpecStore()
                        .load(registryDir, ref, cp.dial().activeRecipeVersion())
                        .orElseThrow(() -> new IllegalStateException("conformance active recipe not in registry: "
                                + ref + "@" + cp.dial().activeRecipeVersion()));
            }
        }
        System.out.println("[BRIDGE] conformance loaded " + cp.equipmentRef() + "@" + cp.equipmentVersion()
                + " dial=" + (cp.dial() == null ? "none" : cp.dial().mode()));
        return new Conformance(cdef, cp, recipe);
    }

    /**
     * Fail-closed ledger trust check before binding the active version. {@code requireSigned=false} →
     * T4 structural chain ({@code verifyChain}); {@code true} → full {@link
     * dev.krillin.bifrost.core.identity.SignedLedgerVerifier} (structural + dual-sig + signed head).
     * {@code SignedLedgerVerifier} runs {@code LedgerChain.verify} first, so structural breaks are still
     * caught when the flag is on. Throws {@link IllegalStateException} with the reason-coded message on a break.
     */
    static void assertLedgerTrustworthy(java.nio.file.Path ledgerDir, String target, boolean requireSigned)
            throws java.io.IOException {
        // Audit line: prove from the log which trust check actually ran before binding (a security toggle
        // must be observable — otherwise a mis-set flag silently downgrades enforcement with no signal).
        System.out.println("[BRIDGE] activation trust = " + (requireSigned ? "signed" : "structural")
                + " (target " + target + ")");
        if (requireSigned) {
            var v = dev.krillin.bifrost.core.identity.SignedLedgerVerifier.forRegistry(ledgerDir).verify(target);
            if (!v.intact())
                throw new IllegalStateException("activation.edge.signed-ledger-broken: target " + target
                        + " index " + v.brokenIndex() + " rule " + v.rule());
        } else {
            var chain = new dev.krillin.bifrost.core.activation.ActivationLedger(ledgerDir).verifyChain(target);
            if (!chain.intact())
                throw new IllegalStateException("activation.edge.ledger-chain-broken: target " + target
                        + " index " + chain.brokenIndex() + " rule " + chain.rule());
        }
    }

    /**
     * Fail-closed activation authZ re-check at the edge (only meaningful with an authenticated subject, i.e.
     * requireSigned). Throws activation.edge.authz-denied on a deny; prints an audit line on pass. No-op when
     * requireSigned is false (authZ presupposes authN).
     */
    static void assertActivationAuthorized(java.nio.file.Path ledgerDir, String target, String kind, String ref,
                                           String activatedBy, String approvedBy, boolean requireSigned) {
        if (!requireSigned) return;
        var policy = dev.krillin.bifrost.core.activation.ActivationPolicyStore.load(ledgerDir);
        var authz = new dev.krillin.bifrost.core.activation.ActivationAuthorizer();
        var a = authz.authorize(policy, activatedBy, dev.krillin.bifrost.core.activation.ActivationAction.ACTIVATE, target, kind, ref);
        if (!a.allowed())
            throw new IllegalStateException("activation.edge.authz-denied: " + activatedBy + " activate [" + a.reason() + "]");
        var p = authz.authorize(policy, approvedBy, dev.krillin.bifrost.core.activation.ActivationAction.APPROVE, target, kind, ref);
        if (!p.allowed())
            throw new IllegalStateException("activation.edge.authz-denied: " + approvedBy + " approve [" + p.reason() + "]");
        System.out.println("[BRIDGE] activation authz = ok (by " + activatedBy + "/" + approvedBy + ")");
    }

    public static void main(String[] args) throws Exception {
        Config config = resolve(System::getenv);

        ObjectMapper mapper = AclMapperFactory.create();
        CommandPolicy policy = mapper.readValue(Path.of(config.policyPath()).toFile(), CommandPolicy.class);
        System.out.println("[BRIDGE] policy loaded " + config.policyPath() + " (rules=" + policy.rules().size()
                + ", default=" + policy.defaultEffect() + ")");

        Conformance conformance = loadConformance(config);

        OpcUaApplier applier = new OpcUaApplier(config.opcua()).connect();
        System.out.println("[BRIDGE] OPC-UA connected " + config.opcua());

        NcmdOpcUaBridge bridge = new NcmdOpcUaBridge(config.group(), config.edge(), policy, applier,
                conformance.def(), conformance.policy(), conformance.recipe());
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                bridge.close();
            } catch (Exception ignore) {
                // best-effort
            }
            applier.close();
        }));

        bridge.connect(config.broker());
        System.out.println("[BRIDGE] ready");
    }

    private static String env(Function<String, String> getenv, String key, String dflt) {
        String v = getenv.apply(key);
        return v != null && !v.isBlank() ? v : dflt;
    }

    private NcmdOpcUaBridgeMain() {}
}
