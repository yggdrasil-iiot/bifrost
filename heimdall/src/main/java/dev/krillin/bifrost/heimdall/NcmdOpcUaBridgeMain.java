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

    /** Resolved runtime configuration — a testable seam around the env lookups below. */
    record Config(String broker, String opcua, String group, String edge, String policyPath,
                  String registryPath, String conformancePath, String activationPath, String activationTarget) {}

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
        return new Config(broker, opcua, group, edge, policyPath, registryPath, conformancePath, activationPath, activationTarget);
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
            recipe = new MasterSpecStore()
                    .load(registryDir, cp.dial().activeRecipeRef(), cp.dial().activeRecipeVersion())
                    .orElseThrow(() -> new IllegalStateException("conformance active recipe not in registry: "
                            + cp.dial().activeRecipeRef() + "@" + cp.dial().activeRecipeVersion()));
        }
        System.out.println("[BRIDGE] conformance loaded " + cp.equipmentRef() + "@" + cp.equipmentVersion()
                + " dial=" + (cp.dial() == null ? "none" : cp.dial().mode()));
        return new Conformance(cdef, cp, recipe);
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
