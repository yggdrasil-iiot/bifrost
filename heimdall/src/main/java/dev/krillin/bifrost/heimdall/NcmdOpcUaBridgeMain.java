package dev.krillin.bifrost.heimdall;

import java.nio.file.Path;
import java.util.function.Function;

import com.fasterxml.jackson.databind.ObjectMapper;

import dev.krillin.bifrost.core.acl.AclMapperFactory;
import dev.krillin.bifrost.core.acl.CommandPolicy;

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
    record Config(String broker, String opcua, String group, String edge, String policyPath) {}

    static Config resolve(Function<String, String> getenv) {
        String broker = env(getenv, "MQTT_URL", "tcp://localhost:1883");
        String opcua = env(getenv, "OPCUA_URL", "opc.tcp://localhost:48400");
        String group = env(getenv, "SPB_GROUP", "Bifrost:Line1");
        String edge = env(getenv, "SPB_EDGE", "recipe-edge");
        String policyPath = env(getenv, "POLICY_PATH", "registry/policy.json");
        return new Config(broker, opcua, group, edge, policyPath);
    }

    public static void main(String[] args) throws Exception {
        Config config = resolve(System::getenv);

        ObjectMapper mapper = AclMapperFactory.create();
        CommandPolicy policy = mapper.readValue(Path.of(config.policyPath()).toFile(), CommandPolicy.class);
        System.out.println("[BRIDGE] policy loaded " + config.policyPath() + " (rules=" + policy.rules().size()
                + ", default=" + policy.defaultEffect() + ")");

        OpcUaApplier applier = new OpcUaApplier(config.opcua()).connect();
        System.out.println("[BRIDGE] OPC-UA connected " + config.opcua());

        NcmdOpcUaBridge bridge = new NcmdOpcUaBridge(config.group(), config.edge(), policy, applier);
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
