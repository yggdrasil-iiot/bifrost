package dev.krillin.bifrost.heimdall;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;

import com.sun.net.httpserver.HttpServer;

/**
 * The edge's own liveness and counters, plus a JDK-only {@code /healthz}.
 *
 * <p>The repo previously had no health surface at all, which meant the two failure modes R0 fixes
 * — a deaf broker connection and an invisible plant — were discoverable only by reading a log
 * file. Health is deliberately the AND of both legs: an edge that is connected to the broker but
 * cannot see the plant answers every command with a refusal, and reporting that as healthy is how
 * a monitoring system learns to lie.
 *
 * <p>No metrics dependency on purpose. The reactor has no metrics stack, and picking one is not
 * this change's decision to make; {@link HttpServer} ships with the JDK.
 */
public final class EdgeHealth {

    private final AtomicLong applied = new AtomicLong();
    private final AtomicLong denied = new AtomicLong();
    private final AtomicLong unreachable = new AtomicLong();

    private volatile boolean broker;
    private volatile boolean plant;
    private volatile Long certDaysRemaining;   // null when no OPC-UA identity is configured
    private HttpServer server;

    public void brokerConnected()    { broker = true; }
    public void brokerDisconnected() { broker = false; }
    public void plantReachable()     { plant = true; }
    public void plantUnreachable()   { plant = false; unreachable.incrementAndGet(); }
    public void applied()            { applied.incrementAndGet(); plant = true; }
    public void denied()             { denied.incrementAndGet(); }

    /**
     * Days until the edge's OPC-UA certificate expires, negative once it has. Null when no identity
     * is configured, in which case the metric is omitted rather than reported as a misleading zero.
     */
    public void certDaysRemaining(long days) { certDaysRemaining = days; }

    /**
     * Deliberately NOT affected by certificate expiry. An expired certificate makes writes fail,
     * which already flips plant_reachable through the applier -- reporting the same fault twice in
     * one boolean makes the signal harder to read, not easier, and would also mean a monitoring
     * system could not tell "the plant is down" from "our certificate lapsed". The days metric is
     * where that distinction lives, and it goes negative long before anyone has to guess.
     */
    public boolean healthy()       { return broker && plant; }
    public long appliedCount()     { return applied.get(); }
    public long deniedCount()      { return denied.get(); }
    public long unreachableCount() { return unreachable.get(); }

    /** Plain text, one metric per line — readable by a human and by a scraper, with no dependency. */
    public String report() {
        Long days = certDaysRemaining;
        return "healthy " + (healthy() ? 1 : 0) + "\n"
             + "broker_connected " + (broker ? 1 : 0) + "\n"
             + "plant_reachable " + (plant ? 1 : 0) + "\n"
             + "applied " + applied.get() + "\n"
             + "denied " + denied.get() + "\n"
             + "plant_unreachable " + unreachable.get() + "\n"
             + (days == null ? "" : "cert_days_remaining " + days + "\n");
    }

    /** @param port the listen port; {@code 0} disables the endpoint entirely. */
    public void startHttp(int port) throws IOException {
        if (port == 0) {
            return;
        }
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/healthz", exchange -> {
            byte[] body = report().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(healthy() ? 200 : 503, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        server.setExecutor(null);
        server.start();
        System.out.println("[BRIDGE] health endpoint on :" + port + "/healthz");
    }

    public void stopHttp() {
        if (server != null) {
            server.stop(0);
        }
    }
}
