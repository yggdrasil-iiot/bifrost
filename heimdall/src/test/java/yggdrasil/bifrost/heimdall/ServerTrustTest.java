package yggdrasil.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The edge trusts exactly the OPC-UA servers an operator placed in its trust list. Two self-signed
 * certificates stand in for the plant's server and a rogue one at the same address: the validator
 * Heimdall installs must accept the first and refuse the second, and an empty list must refuse to
 * start rather than refuse every server at command time.
 */
class ServerTrustTest {

    static final String SERVER_URI = "urn:bifrost:opcua:sim-server";

    @TempDir Path tmp;

    @Test void acceptsATrustedServerAndRefusesAnyOther() throws Exception {
        EdgeIdentity plant = EdgeIdentity.loadOrCreate(tmp.resolve("plant"), SERVER_URI);
        EdgeIdentity rogue = EdgeIdentity.loadOrCreate(tmp.resolve("rogue"), SERVER_URI);
        Path dir = tmp.resolve("trust");
        Files.createDirectories(dir.resolve("trusted/certs"));
        Files.write(dir.resolve("trusted/certs/plant.der"), plant.certificate().getEncoded());

        try (ServerTrust trust = ServerTrust.load(dir)) {
            assertEquals(1, trust.trustedCount());
            trust.validator().validateCertificateChain(List.of(plant.certificate()), SERVER_URI, new String[] { "localhost" });
            UaException refused = assertThrows(UaException.class, () -> trust.validator()
                    .validateCertificateChain(List.of(rogue.certificate()), SERVER_URI, new String[] { "localhost" }));
            assertTrue(refused.getMessage() != null && !refused.getMessage().isBlank(), "the refusal names a cause");
        }
        try (var rejected = Files.list(dir.resolve("rejected"))) {
            assertEquals(1, rejected.count(), "the refused certificate is quarantined for an operator to inspect");
        }
    }

    @Test void anEmptyTrustListRefusesToStart() throws Exception {
        Path dir = tmp.resolve("empty");
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> ServerTrust.load(dir));
        assertTrue(e.getMessage().contains(dir.resolve("trusted/certs").toString()), e.getMessage());
        assertTrue(Files.isDirectory(dir.resolve("trusted/certs")), "the layout is created for the operator to fill");
    }
}
