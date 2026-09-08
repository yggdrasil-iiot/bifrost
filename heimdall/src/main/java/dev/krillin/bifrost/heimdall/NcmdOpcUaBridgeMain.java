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
 *
 *   ENFORCEMENT_LOG_ONLY  false      (rollout mode: log what would be denied, apply it anyway)
 *
 *   HEALTH_PORT            9090      (/healthz; 0 disables the endpoint)
 *   HEIMDALL_APPLY_THREADS 4         (per-node ordering stripes for the apply path)
 *
 *   HEIMDALL_IDENTITY_DIR  (unset)   (OPC-UA keypair + certificate dir; unset = anonymous/None)
 *
 *   REQUIRE_SIGNED_COMMAND false     (every NCMD must carry a verified sub/sig; not shadowed by log-only)
 *   HEIMDALL_REPLAY_WINDOW 1024      (recently-seen command ids kept for replay refusal)
 *
 *   COMMAND_LEDGER_PATH    (unset)   (root of the chained command record; unset = no record)
 *   REQUIRE_COMMAND_LEDGER false     (an unwritable INTENT entry refuses the command)
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
     * {@code requireAnchoredActivation} (env {@code REQUIRE_ANCHORED_ACTIVATION}, default OFF) raises the bar
     * one tier further to {@link dev.krillin.bifrost.core.identity.TrustLevel#ANCHORED} (adds the external
     * anchor cross-check + four-eyes head); it IMPLIES signed (anchored presupposes authN). {@code anchorStore}
     * ({@code ANCHOR_STORE}, file|git) and {@code anchorDir} ({@code ANCHOR_DIR}) pick the anchor witness.
     */
    record Config(String broker, String opcua, String group, String edge, String policyPath,
                  String registryPath, String conformancePath, String activationPath, String activationTarget,
                  boolean requireSignedActivation, boolean requireAnchoredActivation, String anchorStore,
                  String anchorDir, boolean enforcementLogOnly, int healthPort, int applyThreads, String identityDir,
                  boolean requireSignedCommand, int replayWindow,
                  String commandLedgerPath, boolean requireCommandLedger) {}

    /**
     * Tri-state flag parse shared by every boolean env toggle. {@code true/on/1} and {@code false/off/0}
     * are recognized; anything else falls to OFF with a loud WARN, because a mis-set security toggle
     * that silently changes enforcement is worse than either setting.
     *
     * <p>OFF is the safe fall for all three flags as it happens, but for opposite reasons — for the
     * {@code REQUIRE_*} bars OFF is the weaker setting and the WARN is the whole protection, whereas
     * for {@code ENFORCEMENT_LOG_ONLY} OFF is full enforcement.
     */
    private static boolean flag(Function<String, String> getenv, String key, String offNote) {
        String v = env(getenv, key, "false").strip();
        if ("true".equalsIgnoreCase(v) || "on".equalsIgnoreCase(v) || "1".equals(v)) return true;
        boolean off = "false".equalsIgnoreCase(v) || "off".equalsIgnoreCase(v) || "0".equals(v) || v.isEmpty();
        if (!off) System.err.println("[BRIDGE] WARN: " + key + "='" + v + "' not recognized - treating as OFF"
                + offNote + ". Use true/on/1 or false/off/0.");
        return false;
    }

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
        boolean requireSigned = flag(getenv, "REQUIRE_SIGNED_ACTIVATION", " (structural-only)");
        boolean requireAnchored = flag(getenv, "REQUIRE_ANCHORED_ACTIVATION", "");
        boolean requireSignedEffective = requireSigned || requireAnchored;   // anchored presupposes authN
        // Deliberately NOT warned about: log-only together with a REQUIRE_*_ACTIVATION bar. The two are
        // orthogonal -- the bars decide which ledger the edge will trust before it binds, log-only decides
        // whether commands are refused -- so raising the ladder while still in log-only is an ordinary
        // rollout state. The startup line below already says in plain words that nothing is being blocked.
        boolean logOnly = flag(getenv, "ENFORCEMENT_LOG_ONLY", "");
        String anchorStore = env(getenv, "ANCHOR_STORE", "file");
        String anchorDir = env(getenv, "ANCHOR_DIR", null);
        int healthPort = intEnv(getenv, "HEALTH_PORT", 9090);
        int applyThreads = intEnv(getenv, "HEIMDALL_APPLY_THREADS", 4);
        String identityDir = env(getenv, "HEIMDALL_IDENTITY_DIR", null);
        boolean requireSignedCommand = flag(getenv, "REQUIRE_SIGNED_COMMAND", "");
        int replayWindow = intEnv(getenv, "HEIMDALL_REPLAY_WINDOW", 1024);
        String commandLedgerPath = env(getenv, "COMMAND_LEDGER_PATH", null);
        boolean requireCommandLedger = flag(getenv, "REQUIRE_COMMAND_LEDGER", "");
        return new Config(broker, opcua, group, edge, policyPath, registryPath, conformancePath, activationPath,
                activationTarget, requireSignedEffective, requireAnchored, anchorStore, anchorDir, logOnly,
                healthPort, applyThreads, identityDir, requireSignedCommand, replayWindow,
                commandLedgerPath, requireCommandLedger);
    }

    /**
     * The OPC-UA application URI this edge announces, derived rather than configured.
     *
     * <p>Per-edge on purpose: two edges must be two principals to the server, or a per-edge write
     * permission cannot mean anything. Separators are folded for the same reason they are in
     * {@code NcmdOpcUaBridge.clientId}.
     *
     * <p>It is derived in exactly one place because the same value has to reach BOTH the
     * certificate's subjectAltName and the announced application URI. A mismatch between the two is
     * rejected at connect time with an error that reads like a server fault.
     */
    static String applicationUri(String group, String edge) {
        // Fold each segment BEFORE joining: a group such as "Bifrost:Line1" carries the same
        // separator this URI uses, so folding the joined string would be ambiguous.
        return "urn:bifrost:heimdall:" + foldSegment(group) + ":" + foldSegment(edge);
    }

    private static String foldSegment(String s) {
        return s == null ? "" : s.replaceAll("[:/]", "-");
    }

    /**
     * Integer env parse sharing the {@link #flag} idiom: an unparseable value falls to the default
     * with a loud WARN rather than silently becoming something else. A health port that quietly
     * moves is the same class of bug as a mis-set security toggle — you find out from the symptom.
     */
    private static int intEnv(Function<String, String> getenv, String key, int dflt) {
        String v = env(getenv, key, null);
        if (v == null || v.isBlank()) {
            return dflt;
        }
        try {
            return Integer.parseInt(v.strip());
        } catch (NumberFormatException e) {
            System.err.println("[BRIDGE] WARN: " + key + "='" + v + "' is not a number - using " + dflt);
            return dflt;
        }
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
                assertLedgerTrustworthy(ledgerDir, config.activationTarget(), config.requireSignedActivation(),
                        config.requireAnchoredActivation(), config.anchorStore(), config.anchorDir());
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
     * Fail-closed ledger trust check before binding the active version. Three opt-in tiers, highest first:
     * {@code requireAnchored=true} → full {@link dev.krillin.bifrost.core.identity.SignedLedgerVerifier} at
     * {@link dev.krillin.bifrost.core.identity.TrustLevel#ANCHORED} (structural + dual-sig + external anchor
     * cross-check + four-eyes head), fail-closing {@code activation.edge.anchor-denied} on a rollback/behind
     * anchor fault; else {@code requireSigned=true} → {@code SignedLedgerVerifier.verify} (structural +
     * dual-sig + signed head); else T4 structural chain ({@code verifyChain}). {@code SignedLedgerVerifier}
     * runs {@code LedgerChain.verify} first, so structural breaks are still caught in the higher tiers.
     * Throws {@link IllegalStateException} with the reason-coded message on a break.
     */
    static void assertLedgerTrustworthy(java.nio.file.Path ledgerDir, String target, boolean requireSigned,
                                        boolean requireAnchored, String anchorStoreKind, String anchorDir)
            throws java.io.IOException {
        // Audit line: prove from the log which trust check actually ran before binding (a security toggle
        // must be observable — otherwise a mis-set flag silently downgrades enforcement with no signal).
        System.out.println("[BRIDGE] activation trust = "
                + (requireAnchored ? "anchored" : requireSigned ? "signed" : "structural")
                + " (target " + target + ")");
        if (requireAnchored) {
            java.nio.file.Path anchorRepo = (anchorDir != null && !anchorDir.isBlank())
                    ? java.nio.file.Path.of(anchorDir) : ledgerDir;
            if ("git".equals(anchorStoreKind)
                    && dev.krillin.bifrost.core.identity.GitAnchorStore.isColocatedWith(anchorRepo, ledgerDir))
                System.err.println("[BRIDGE] WARN: git anchor repo " + anchorRepo + " is inside the registry "
                        + ledgerDir + " - a registry rollback rolls back this witness too; the co-rollback (#2)"
                        + " guarantee is NOT in force. Set ANCHOR_DIR to a separate off-box protected repo.");
            dev.krillin.bifrost.core.activation.AnchorStore anchors = "git".equals(anchorStoreKind)
                    ? new dev.krillin.bifrost.core.identity.GitAnchorStore(anchorRepo)
                    : new dev.krillin.bifrost.core.activation.FileAnchorStore(anchorRepo);
            var v = dev.krillin.bifrost.core.identity.SignedLedgerVerifier.forRegistry(ledgerDir)
                    .verify(target, dev.krillin.bifrost.core.identity.TrustLevel.ANCHORED, anchors);
            if (!v.intact())
                throw new IllegalStateException("activation.edge.anchor-denied reason=" + v.rule()
                        + " (target " + target + " index " + v.brokenIndex() + ")");
            return;
        }
        if (requireSigned) {
            var v = dev.krillin.bifrost.core.identity.SignedLedgerVerifier.forRegistry(ledgerDir).verify(target);
            if (!v.intact())
                throw new IllegalStateException("activation.edge.signed-ledger-broken: target " + target
                        + " index " + v.brokenIndex() + " rule " + v.rule());
            return;
        }
        var chain = new dev.krillin.bifrost.core.activation.ActivationLedger(ledgerDir).verifyChain(target);
        if (!chain.intact())
            throw new IllegalStateException("activation.edge.ledger-chain-broken: target " + target
                    + " index " + chain.brokenIndex() + " rule " + chain.rule());
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
        // Same rule as the activation-trust audit line: a toggle that changes enforcement must be
        // readable from the log. This is the most consequential one in the system, so it prints in
        // both states rather than only when it is on.
        System.out.println("[BRIDGE] enforcement = " + (config.enforcementLogOnly()
                ? "LOG-ONLY: commands that would be denied are APPLIED (rollout mode, see docs/ADOPTION.md)"
                : "enforcing"));

        Conformance conformance = loadConformance(config);

        EdgeHealth health = new EdgeHealth();

        // Connect eagerly so a healthy start is still reported as one, but do NOT die if the plant
        // is down: a site power event restarts the OPC-UA server and this edge together, and an
        // edge that exits here crash-loops under a restart policy instead of waiting. The applier's
        // lazy reconnect brings the session up on the first command that needs it.
        //
        // This does not weaken the startup ledger-trust checks above. Those still fail closed, and
        // deliberately so: an invisible machine is transient, an untrustworthy model is not.
        // The edge's OPC-UA identity, when one is configured. Derived URI, so the certificate's
        // subjectAltName and the announced application URI can never disagree.
        EdgeIdentity identity = null;
        if (config.identityDir() != null && !config.identityDir().isBlank()) {
            identity = EdgeIdentity.loadOrCreate(Path.of(config.identityDir()),
                    applicationUri(config.group(), config.edge()));
            // Printed so an operator can match this against what the server has been told to trust.
            // Without it, a thumbprint mismatch looks like an ordinary connection failure.
            System.out.println("[BRIDGE] OPC-UA identity " + identity.thumbprint()
                    + " (" + identity.applicationUri() + ")");
        }

        // Loaded ONCE, like the policy and the ledger above it: revocation latency is therefore the
        // next edge restart, which is the boundary ENTERPRISE.md §2 already documents rather than a
        // second, quieter rule invented here. Reading the file per command would also make the write
        // path depend on the filesystem at command time.
        final dev.krillin.bifrost.core.identity.AuthorizedKeys keys =
                dev.krillin.bifrost.core.identity.AuthorizedKeys.load(Path.of(config.registryPath()));
        java.util.function.Function<String, java.security.PublicKey> trustAnchor =
                name -> keys.forPrincipal(name).orElse(null);
        if (config.requireSignedCommand()) {
            System.out.println("[BRIDGE] REQUIRE_SIGNED_COMMAND on - every command must carry a verified"
                    + " sub/sig (trust anchor: " + config.registryPath() + "/identity/authorized-keys.jsonl)");
        }

        dev.krillin.bifrost.core.command.CommandLedger commandLedger = null;
        if (config.commandLedgerPath() != null && !config.commandLedgerPath().isBlank()) {
            commandLedger = new dev.krillin.bifrost.core.command.CommandLedger(
                    Path.of(config.commandLedgerPath()), java.time.Clock.systemUTC());
            System.out.println("[BRIDGE] command ledger at " + config.commandLedgerPath()
                    + (config.requireCommandLedger() ? " (REQUIRED: an unwritable entry refuses)" : ""));
        }

        OpcUaApplier applier = new OpcUaApplier(config.opcua(), health, identity);
        try {
            applier.connect();
            System.out.println("[BRIDGE] OPC-UA connected " + config.opcua());
        } catch (Exception plantDown) {
            System.out.println("[BRIDGE] OPC-UA not reachable at start (" + plantDown.getMessage()
                    + ") - starting anyway, commands will answer plant-unreachable until it returns");
        }

        NcmdOpcUaBridge bridge = new NcmdOpcUaBridge(config.group(), config.edge(), policy, applier,
                conformance.def(), conformance.policy(), conformance.recipe(), config.enforcementLogOnly(),
                health, config.applyThreads(), 64,
                config.requireSignedCommand(), config.replayWindow(), trustAnchor,
                commandLedger, config.requireCommandLedger());
        health.startHttp(config.healthPort());
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                bridge.close();
            } catch (Exception ignore) {
                // best-effort
            }
            applier.close();
            health.stopHttp();
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
