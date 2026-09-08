package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EdgeIdentityTest {

    private static final String URI = "urn:bifrost:heimdall:test";

    @Test
    void generatesAKeypairAndCertificateOnFirstUse(@TempDir Path dir) throws Exception {
        EdgeIdentity id = EdgeIdentity.loadOrCreate(dir, URI);
        assertNotNull(id.certificate());
        assertNotNull(id.keyPair());
        assertTrue(Files.exists(dir.resolve("edge-cert.der")), "the certificate must be persisted");
        assertTrue(Files.exists(dir.resolve("edge-key.pkcs8")), "the private key must be persisted");
    }

    /** The identity has to survive a restart, or every restart is a new principal to the server. */
    @Test
    void reloadsTheSameIdentity(@TempDir Path dir) throws Exception {
        EdgeIdentity first = EdgeIdentity.loadOrCreate(dir, URI);
        EdgeIdentity again = EdgeIdentity.loadOrCreate(dir, URI);
        assertArrayEquals(first.certificate().getEncoded(), again.certificate().getEncoded(),
                "a restart must present the SAME certificate, not a new one");
        assertEquals(first.thumbprint(), again.thumbprint());
    }

    @Test
    void thumbprintIsASha1HexOfTheEncodedCertificate(@TempDir Path dir) throws Exception {
        EdgeIdentity id = EdgeIdentity.loadOrCreate(dir, URI);
        assertEquals(40, id.thumbprint().length(), "SHA-1 hex is 40 chars: " + id.thumbprint());
        assertTrue(id.thumbprint().matches("[0-9a-f]{40}"), id.thumbprint());
    }

    /**
     * The application URI in the certificate must match the one the client announces, or Milo
     * rejects its own certificate at connect time with a validation failure that reads like a
     * server problem.
     */
    @Test
    void certificateCarriesTheApplicationUriAsASubjectAltName(@TempDir Path dir) throws Exception {
        EdgeIdentity id = EdgeIdentity.loadOrCreate(dir, URI);
        assertNotNull(id.certificate().getSubjectAlternativeNames(), "no SANs at all on the certificate");
        boolean found = id.certificate().getSubjectAlternativeNames().stream()
                .anyMatch(e -> URI.equals(String.valueOf(e.get(1))));
        assertTrue(found, "application URI missing from SAN: " + id.certificate().getSubjectAlternativeNames());
    }

    @Test
    void applicationUriIsCarriedOnTheIdentity(@TempDir Path dir) throws Exception {
        assertEquals(URI, EdgeIdentity.loadOrCreate(dir, URI).applicationUri());
    }
}
