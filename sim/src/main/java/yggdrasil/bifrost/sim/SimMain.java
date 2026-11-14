package yggdrasil.bifrost.sim;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Standalone process entry point for the bifrost-local runtime gate: starts the embedded Milo
 * OPC-UA server (endpoint configurable via SIM_BIND_PORT / SIM_BIND_HOST env, default
 * opc.tcp://localhost:48400), prints the ready line the gate waits on, then blocks forever.
 *
 * <p>Run: {@code java -jar bifrost-sim.jar}  (or {@code SIM_BIND_PORT=48401 java -jar bifrost-sim.jar});
 * the scan period is {@code java -Dbifrost.sim.scanMs=50 -jar bifrost-sim.jar}.
 */
public final class SimMain {

    public static void main(String[] args) throws Exception {
        int port = resolvePort(System.getenv());
        String host = resolveHost(System.getenv());
        // Resolved once, before anything starts: a bad value stops the process here with a message.
        long scanMs = resolveScanMs(System.getProperty(SCAN_MS_PROPERTY));
        EmbeddedMiloSim sim = new EmbeddedMiloSim(port, host,
                resolveRequireIdentity(System.getenv()), resolveGovernedThumbprint(System.getenv()),
                scanMs).start();
        Runtime.getRuntime().addShutdownHook(new Thread(sim::close));
        String certOut = System.getenv("SIM_SERVER_CERT_OUT");
        if (certOut != null && !certOut.isBlank()) {
            exportServerCertificate(sim, certOut.trim());
        }

        // The gate waits for the substring "OPC-UA sim listening" — keep this line stable.
        System.out.println("OPC-UA sim listening on opc.tcp://" + host + ":" + port);

        Thread.currentThread().join();
    }

    static final String SCAN_MS_PROPERTY = "bifrost.sim.scanMs";

    /**
     * {@code -Dbifrost.sim.scanMs=<ms>} - the scan period, integer milliseconds 1..86400000. Absent
     * means the default {@link EmbeddedMiloSim.SimNamespace#SCAN_MS} (1000).
     *
     * <p>Every other value is either accepted exactly or refused with a message naming the
     * property; there is no fallback. Unlike {@code SIM_REQUIRE_IDENTITY}, a wrong scan period has
     * no safe default to fall to: the scenario driver writes against the scan boundary, and a sim
     * that quietly ran at 1000 ms when 50 was asked would make every timing assertion downstream
     * fail for a reason that is not in the system under test.
     */
    static long resolveScanMs(String raw) {
        if (raw == null) {
            return EmbeddedMiloSim.SimNamespace.SCAN_MS;
        }
        long v;
        try {
            v = Long.parseLong(raw.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(SCAN_MS_PROPERTY + "='" + raw
                    + "' is not an integer number of milliseconds", e);
        }
        if (v < EmbeddedMiloSim.MIN_SCAN_MS || v > EmbeddedMiloSim.MAX_SCAN_MS) {
            throw new IllegalArgumentException(SCAN_MS_PROPERTY + "=" + v + " is outside "
                    + EmbeddedMiloSim.MIN_SCAN_MS + ".." + EmbeddedMiloSim.MAX_SCAN_MS);
        }
        return v;
    }

    static int resolvePort(Map<String, String> env) {
        String v = env.get("SIM_BIND_PORT");
        return (v == null || v.isBlank()) ? EmbeddedMiloSim.BIND_PORT : Integer.parseInt(v.trim());
    }

    static String resolveHost(Map<String, String> env) {
        String v = env.get("SIM_BIND_HOST");
        return (v == null || v.isBlank()) ? EmbeddedMiloSim.DEFAULT_BIND_HOST : v.trim();
    }

    /**
     * {@code SIM_REQUIRE_IDENTITY} — add a Basic256Sha256/SignAndEncrypt endpoint that requires the
     * governed X.509 identity, and make the controlled nodes read-only for everyone else.
     *
     * <p>Default OFF, and that matters: every gate written before this existed runs against the
     * anonymous endpoint, and they stay meaningful only because this round adds a capability rather
     * than changing the posture. An unrecognised value falls OFF with a loud warning, matching
     * heimdall's {@code flag()} — a typo in a security toggle must not silently mean "off".
     */
    static boolean resolveRequireIdentity(Map<String, String> env) {
        String v = env.get("SIM_REQUIRE_IDENTITY");
        if (v == null || v.isBlank()) {
            return false;
        }
        String t = v.trim();
        if ("on".equalsIgnoreCase(t) || "true".equalsIgnoreCase(t) || "1".equals(t)) {
            return true;
        }
        if (!("off".equalsIgnoreCase(t) || "false".equalsIgnoreCase(t) || "0".equals(t))) {
            System.err.println("[SIM] WARN: SIM_REQUIRE_IDENTITY='" + v
                    + "' not recognized - treating as OFF. Use true/on/1 or false/off/0.");
        }
        return false;
    }

    /** {@code SIM_GOVERNED_THUMBPRINT} — the certificate thumbprints permitted to write, comma-separated.
     *  A list rather than one value because a real server's trust list is one, and because a self-signed
     *  certificate cannot be renewed without changing its thumbprint: with a single value every renewal
     *  is a cutover with no overlap, and the server stops trusting the edge at the exact moment the edge
     *  starts presenting the new certificate. */
    static String resolveGovernedThumbprint(Map<String, String> env) {
        String v = env.get("SIM_GOVERNED_THUMBPRINT");
        return (v == null || v.isBlank()) ? null : v.trim();
    }

    /**
     * {@code SIM_SERVER_CERT_OUT} — write the secured endpoint's certificate (DER) here, before the
     * ready line. The certificate is minted fresh on every start, so this is how a gate puts exactly
     * this server, and no other, into the edge's trust list.
     */
    static void exportServerCertificate(EmbeddedMiloSim sim, String out) throws Exception {
        if (sim.serverCertificate() == null) {
            throw new IllegalStateException("SIM_SERVER_CERT_OUT is set but the sim has no secured endpoint;"
                    + " set SIM_REQUIRE_IDENTITY=on");
        }
        Path path = Path.of(out);
        if (path.getParent() != null) {
            Files.createDirectories(path.getParent());
        }
        Files.write(path, sim.serverCertificate().getEncoded());
    }

    private SimMain() {}
}
