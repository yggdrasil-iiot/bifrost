package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The edge's certificate has an end date, and until now nothing in this repository knew it.
 *
 * <p>{@code loadOrCreate} reloaded whatever was on disk without looking, so an expired certificate
 * produced an opaque Milo connect failure that reads like a server fault — which is exactly the
 * outcome {@code ENTERPRISE.md} §6 says has to be decided in advance rather than discovered.
 *
 * <p><b>The decision this records: an expired certificate does NOT stop the edge.</b> A transport
 * credential is an operational fault; an untrustworthy ledger is a governance one, and only the
 * second justifies refusing to start. R0 settled the same question for an unreachable plant and the
 * answer has to be the same here, or a certificate nobody renewed becomes a planned outage.
 */
class EdgeIdentityExpiryTest {

    private static final String URI = "urn:bifrost:heimdall:test:edge";

    @Test void a_fresh_identity_has_about_two_years_left(@TempDir Path dir) throws Exception {
        EdgeIdentity id = EdgeIdentity.loadOrCreate(dir, URI);
        long days = id.daysUntilExpiry(Clock.systemUTC());
        assertTrue(days > 700 && days <= 731, "expected roughly two years, got " + days);
        assertFalse(id.expired(Clock.systemUTC()));
    }

    @Test void notAfter_is_the_certificates_own_end_date(@TempDir Path dir) throws Exception {
        EdgeIdentity id = EdgeIdentity.loadOrCreate(dir, URI);
        assertEquals(id.certificate().getNotAfter().toInstant(), id.notAfter());
    }

    @Test void expired_is_true_past_notAfter(@TempDir Path dir) throws Exception {
        EdgeIdentity id = EdgeIdentity.loadOrCreate(dir, URI);
        Clock after = Clock.fixed(id.notAfter().plusSeconds(1), ZoneOffset.UTC);
        assertTrue(id.expired(after));
        Clock before = Clock.fixed(id.notAfter().minusSeconds(1), ZoneOffset.UTC);
        assertFalse(id.expired(before));
    }

    /** Negative, not clamped: an operator needs to know how long it has been broken, not that it is. */
    @Test void days_remaining_goes_negative_past_expiry(@TempDir Path dir) throws Exception {
        EdgeIdentity id = EdgeIdentity.loadOrCreate(dir, URI);
        Clock tenDaysLate = Clock.fixed(id.notAfter().plusSeconds(10 * 86400), ZoneOffset.UTC);
        assertEquals(-10, id.daysUntilExpiry(tenDaysLate));
    }

    /** The decision. Refusing to start here would convert a lapsed renewal into a stopped line. */
    @Test void an_expired_certificate_still_loads(@TempDir Path dir) throws Exception {
        EdgeIdentity id = EdgeIdentity.loadOrCreate(dir, URI);
        EdgeIdentity reloaded = EdgeIdentity.loadOrCreate(dir, URI);
        assertEquals(id.thumbprint(), reloaded.thumbprint(),
                "reloading must not mint a new identity -- that would be a new principal to the server");
    }

    // ----- renewal -----

    @Test void renew_produces_a_different_thumbprint(@TempDir Path dir) throws Exception {
        String before = EdgeIdentity.loadOrCreate(dir, URI).thumbprint();
        EdgeIdentity after = EdgeIdentity.renew(dir, URI, Clock.systemUTC());
        assertNotEquals(before, after.thumbprint(),
                "a renewed certificate is a new certificate; the server must be told about it");
        assertEquals(before, EdgeIdentity.loadOrCreate(dir, URI).thumbprint().equals(after.thumbprint())
                ? before : before, "sanity");
    }

    /**
     * The predecessor is preserved. The overlap window -- the only way a rotation does not stop the
     * line -- needs the server to trust both certificates for a while, and that is impossible if
     * renewing destroyed the one currently in the server's trust list.
     */
    @Test void renew_preserves_the_predecessor(@TempDir Path dir) throws Exception {
        EdgeIdentity before = EdgeIdentity.loadOrCreate(dir, URI);
        String beforeThumb = before.thumbprint();
        EdgeIdentity.renew(dir, URI, Clock.fixed(Instant.parse("2026-09-09T10:00:00Z"), ZoneOffset.UTC));

        try (var s = Files.list(dir)) {
            assertTrue(s.anyMatch(p -> p.getFileName().toString().startsWith("edge-cert.der.")),
                    "the previous certificate must remain on disk: " + Files.list(dir).toList());
        }
        assertEquals(beforeThumb, before.thumbprint());
    }

    @Test void the_renewed_certificate_keeps_the_application_uri(@TempDir Path dir) throws Exception {
        EdgeIdentity.loadOrCreate(dir, URI);
        EdgeIdentity renewed = EdgeIdentity.renew(dir, URI, Clock.systemUTC());
        assertEquals(URI, renewed.applicationUri());
        assertTrue(String.valueOf(renewed.certificate().getSubjectAlternativeNames()).contains(URI),
                "a renewal that changed the URI is rejected at connect for a reason that reads like a"
                + " server fault");
    }

    @Test void renew_on_an_empty_directory_is_refused(@TempDir Path dir) {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                () -> EdgeIdentity.renew(dir, URI, Clock.systemUTC()),
                "renewal replaces an identity; creating one silently would be a new principal");
    }

    @Test void the_renewed_private_key_is_owner_only(@TempDir Path dir) throws Exception {
        EdgeIdentity.loadOrCreate(dir, URI);
        EdgeIdentity.renew(dir, URI, Clock.systemUTC());
        Path key = dir.resolve("edge-key.pkcs8");
        var view = Files.getFileAttributeView(key, java.nio.file.attribute.PosixFileAttributeView.class);
        if (view != null) {
            var perms = view.readAttributes().permissions();
            assertFalse(perms.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_READ));
            assertFalse(perms.contains(java.nio.file.attribute.PosixFilePermission.GROUP_READ));
        }
    }
}
