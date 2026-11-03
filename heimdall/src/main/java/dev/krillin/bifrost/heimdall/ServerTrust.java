package dev.krillin.bifrost.heimdall;

import java.io.IOException;
import java.nio.file.Path;
import org.eclipse.milo.opcua.stack.core.security.CertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.DefaultClientCertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.FileBasedCertificateQuarantine;
import org.eclipse.milo.opcua.stack.core.security.FileBasedTrustListManager;

/**
 * The OPC-UA servers this edge will talk to, as an operator-managed trust list.
 *
 * <p>Milo's client defaults to a validator that accepts any server certificate. An edge presenting
 * its identity to whoever answers at {@code OPCUA_URL} would sign and execute commands against a
 * rogue server as readily as against the plant, so the governed path installs this instead: a
 * certificate must chain to an entry under {@code trusted/certs} (or to an issuer under
 * {@code issuer/certs}), and anything else is refused before the session opens and copied to
 * {@code rejected/} for an operator to inspect.
 *
 * <p>The directory follows the OPC-UA PKI layout Milo's file-based trust list reads
 * ({@code trusted/certs}, {@code trusted/crl}, {@code issuer/certs}, {@code issuer/crl}); the layout
 * is created on first use. An empty list refuses to start: it would refuse every server, and the
 * symptom an operator would see at command time is "plant unreachable", which names the wrong cause.
 */
public final class ServerTrust implements AutoCloseable {

    private final FileBasedTrustListManager trustList;
    private final CertificateValidator validator;

    private ServerTrust(FileBasedTrustListManager trustList, CertificateValidator validator) {
        this.trustList = trustList;
        this.validator = validator;
    }

    public static ServerTrust load(Path dir) throws IOException {
        FileBasedTrustListManager trustList = FileBasedTrustListManager.createAndInitialize(dir);
        if (trustList.getTrustedCertificates().isEmpty() && trustList.getIssuerCertificates().isEmpty()) {
            trustList.close();
            throw new IllegalStateException("no OPC-UA server is trusted: place the server's certificate (DER) in "
                    + dir.resolve("trusted/certs"));
        }
        FileBasedCertificateQuarantine quarantine = FileBasedCertificateQuarantine.create(dir.resolve("rejected"));
        return new ServerTrust(trustList, new DefaultClientCertificateValidator(trustList, quarantine));
    }

    public CertificateValidator validator() {
        return validator;
    }

    public int trustedCount() {
        return trustList.getTrustedCertificates().size();
    }

    @Override
    public void close() throws IOException {
        trustList.close();
    }
}
