package dev.krillin.bifrost.sim;

import java.util.Map;

/**
 * Standalone process entry point for the bifrost-local runtime gate: starts the embedded Milo
 * OPC-UA server (endpoint configurable via SIM_BIND_PORT / SIM_BIND_HOST env, default
 * opc.tcp://localhost:48400), prints the ready line the gate waits on, then blocks forever.
 *
 * <p>Run: {@code java -jar bifrost-sim.jar}  (or {@code SIM_BIND_PORT=48401 java -jar bifrost-sim.jar})
 */
public final class SimMain {

    public static void main(String[] args) throws Exception {
        int port = resolvePort(System.getenv());
        String host = resolveHost(System.getenv());
        EmbeddedMiloSim sim = new EmbeddedMiloSim(port, host).start();
        Runtime.getRuntime().addShutdownHook(new Thread(sim::close));

        // The gate waits for the substring "OPC-UA sim listening" — keep this line stable.
        System.out.println("OPC-UA sim listening on opc.tcp://" + host + ":" + port);

        Thread.currentThread().join();
    }

    static int resolvePort(Map<String, String> env) {
        String v = env.get("SIM_BIND_PORT");
        return (v == null || v.isBlank()) ? EmbeddedMiloSim.BIND_PORT : Integer.parseInt(v.trim());
    }

    static String resolveHost(Map<String, String> env) {
        String v = env.get("SIM_BIND_HOST");
        return (v == null || v.isBlank()) ? EmbeddedMiloSim.DEFAULT_BIND_HOST : v.trim();
    }

    private SimMain() {}
}
