package dev.krillin.bifrost.sim;

/**
 * Standalone process entry point for the bifrost-local runtime gate: starts the embedded Milo
 * OPC-UA server, prints the ready line the gate waits on, then blocks forever (until killed).
 *
 * <p>Run: {@code java -jar bifrost-sim.jar}
 */
public final class SimMain {

    public static void main(String[] args) throws Exception {
        EmbeddedMiloSim sim = new EmbeddedMiloSim().start();
        Runtime.getRuntime().addShutdownHook(new Thread(sim::close));

        // The gate waits for the substring "OPC-UA sim listening" — keep this line stable.
        System.out.println("OPC-UA sim listening on opc.tcp://localhost:" + EmbeddedMiloSim.BIND_PORT);

        Thread.currentThread().join();
    }

    private SimMain() {
    }
}
