package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Renewal is an OPERATOR command, not a startup flag.
 *
 * <p>A restart that could mint an identity is a restart that can silently turn the edge into a new
 * principal to the server — the failure {@code loadOrCreate}'s reload-rather-than-regenerate rule
 * exists to prevent. So renewal is something a person runs, at a moment they chose, and it prints
 * both thumbprints because the server's trust list is the thing that actually has to change.
 */
class EdgeIdentityCliTest {

    private static final String URI = "urn:bifrost:heimdall:test:edge";

    private record Run(int code, String out) {
    }

    private static Run run(String... args) throws Exception {
        PrintStream saved = System.out;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int code;
        try {
            System.setOut(new PrintStream(buf, true, StandardCharsets.UTF_8));
            code = EdgeIdentity.run(args);
        } finally {
            System.setOut(saved);
        }
        return new Run(code, buf.toString(StandardCharsets.UTF_8));
    }

    @Test void show_reports_the_thumbprint_and_days_remaining(@TempDir Path dir) throws Exception {
        String thumb = EdgeIdentity.loadOrCreate(dir, URI).thumbprint();
        Run r = run("show", dir.toString(), URI);
        assertEquals(0, r.code());
        assertTrue(r.out().contains(thumb), r.out());
        assertTrue(r.out().contains("notAfter"), r.out());
        assertTrue(r.out().toLowerCase(java.util.Locale.ROOT).contains("days"), r.out());
    }

    @Test void show_on_an_empty_directory_is_an_error_not_a_silent_create(@TempDir Path dir)
            throws Exception {
        assertEquals(2, run("show", dir.toString(), URI).code());
        assertTrue(java.nio.file.Files.notExists(dir.resolve("edge-cert.der")),
                "inspecting an identity must never create one");
    }

    @Test void renew_prints_both_thumbprints(@TempDir Path dir) throws Exception {
        String before = EdgeIdentity.loadOrCreate(dir, URI).thumbprint();
        Run r = run("renew", dir.toString(), URI);
        assertEquals(0, r.code());
        String after = EdgeIdentity.loadOrCreate(dir, URI).thumbprint();
        assertNotEquals(before, after);
        assertTrue(r.out().contains(before), "the predecessor thumbprint: " + r.out());
        assertTrue(r.out().contains(after), "the successor thumbprint: " + r.out());
    }

    /** The order is the whole procedure: trust the successor FIRST, restart the edge SECOND. */
    @Test void renew_says_the_server_must_be_told_before_the_edge_restarts(@TempDir Path dir)
            throws Exception {
        EdgeIdentity.loadOrCreate(dir, URI);
        Run r = run("renew", dir.toString(), URI);
        String lower = r.out().toLowerCase(java.util.Locale.ROOT);
        assertTrue(lower.contains("trust list") || lower.contains("trust"), r.out());
        assertTrue(lower.contains("before"), "the ordering must be spelled out: " + r.out());
    }

    @Test void renew_on_an_empty_directory_is_an_error(@TempDir Path dir) throws Exception {
        assertEquals(2, run("renew", dir.toString(), URI).code());
    }

    /** The write-exclusivity gate calls this; it must keep working exactly as it did. */
    @Test void print_thumbprint_still_works(@TempDir Path dir) throws Exception {
        Run r = run("--print-thumbprint", dir.toString(), URI);
        assertEquals(0, r.code());
        assertEquals(EdgeIdentity.loadOrCreate(dir, URI).thumbprint(), r.out().strip());
    }

    @Test void an_unknown_subcommand_is_a_usage_error(@TempDir Path dir) throws Exception {
        assertEquals(2, run("frobnicate", dir.toString(), URI).code());
        assertEquals(2, run().code());
    }
}
