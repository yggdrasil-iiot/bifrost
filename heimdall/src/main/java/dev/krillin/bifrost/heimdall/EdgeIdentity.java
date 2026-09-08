package dev.krillin.bifrost.heimdall;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Period;
import java.util.EnumSet;
import java.util.Set;

import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateBuilder;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateGenerator;

/**
 * The edge's OPC-UA application-instance identity: an RSA keypair and a self-signed certificate,
 * generated once into a directory and reloaded on every start thereafter.
 *
 * <p>This exists because {@code docs/ENTERPRISE.md} row 12 asks a plant to make its controlled
 * nodes writable only by a governed identity — and until now Heimdall had no identity to present,
 * so following that instruction would have locked out the very edge it was meant to privilege.
 * That is why row 12 was not, as both documents claimed, work this repository did not owe.
 *
 * <p><b>Self-signed, and that is a real limitation rather than a shortcut to forget.</b> There is
 * no CA, no rotation, no revocation and no Global Discovery Server here. Trust is established by
 * the server being told this certificate's thumbprint. That is row 10, it is still open, and this
 * class is what makes it bite: an identity that cannot be rotated is a deployment that cannot
 * outlive it.
 *
 * <p>Reloading rather than regenerating is load-bearing. A restart that minted a new certificate
 * would be a new principal to the server, so every restart would need the server reconfigured.
 */
public final class EdgeIdentity {

    private static final String CERT_FILE = "edge-cert.der";
    private static final String KEY_FILE = "edge-key.pkcs8";

    private final X509Certificate certificate;
    private final KeyPair keyPair;
    private final String applicationUri;

    private EdgeIdentity(X509Certificate certificate, KeyPair keyPair, String applicationUri) {
        this.certificate = certificate;
        this.keyPair = keyPair;
        this.applicationUri = applicationUri;
    }

    public X509Certificate certificate() {
        return certificate;
    }

    public KeyPair keyPair() {
        return keyPair;
    }

    public String applicationUri() {
        return applicationUri;
    }

    /**
     * Lowercase hex of {@code SHA-1(certificate)} — the OPC-UA certificate thumbprint.
     *
     * <p>SHA-1 because that is what the OPC-UA specification defines a thumbprint to be, not
     * because it is being chosen here as a security primitive. It identifies a certificate; it does
     * not authenticate one.
     */
    public String thumbprint() {
        try {
            byte[] d = MessageDigest.getInstance("SHA-1").digest(certificate.getEncoded());
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("cannot compute certificate thumbprint", e);
        }
    }

    /** Load the identity in {@code dir}, generating and persisting one if it is not there yet. */
    public static EdgeIdentity loadOrCreate(Path dir, String applicationUri) throws Exception {
        createPrivateDirectory(dir);
        Path certPath = dir.resolve(CERT_FILE);
        Path keyPath = dir.resolve(KEY_FILE);

        if (Files.exists(certPath) && Files.exists(keyPath)) {
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(certPath)));
            PrivateKey priv = KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(keyPath)));
            return new EdgeIdentity(cert, new KeyPair(cert.getPublicKey(), priv), applicationUri);
        }

        KeyPair kp = SelfSignedCertificateGenerator.generateRsaKeyPair(2048);
        // setApplicationUri also places the URI in the subjectAltName, which is what an OPC-UA peer
        // checks against the announced application URI. A mismatch there is rejected at connect
        // time with an error that reads like a server fault, so the two must be set from one value.
        X509Certificate cert = new SelfSignedCertificateBuilder(kp)
                .setCommonName("Bifrost Heimdall Edge")
                .setOrganization("yggdrasil-iiot")
                .setApplicationUri(applicationUri)
                .setValidityPeriod(Period.ofYears(2))
                .setSignatureAlgorithm(SelfSignedCertificateBuilder.SA_SHA256_RSA)
                .build();

        Files.write(certPath, cert.getEncoded());   // the certificate is public by design
        writePrivateKey(keyPath, kp.getPrivate().getEncoded());
        return new EdgeIdentity(cert, kp, applicationUri);
    }

    /**
     * {@code java -cp bifrost-heimdall.jar …EdgeIdentity --print-thumbprint <dir> <applicationUri>}
     * — generate the identity if absent, then print only its thumbprint.
     *
     * <p>Exists for the write-exclusivity gate, which has to start the SERVER already trusting the
     * client's thumbprint. Without this the gate would have to start the edge first against a
     * server that is not up, scrape its log, then start the server — which works only because the
     * edge tolerates a down plant, and leans on a reconnect backoff for no reason.
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 3 || !"--print-thumbprint".equals(args[0])) {
            System.err.println("usage: EdgeIdentity --print-thumbprint <dir> <applicationUri>");
            System.exit(2);
        }
        System.out.println(loadOrCreate(Path.of(args[1]), args[2]).thumbprint());
    }

    /**
     * Create the identity directory owner-only where the filesystem supports it.
     *
     * <p>This whole round is about the edge holding a credential no one else holds. A key file the
     * rest of the machine can read is not that, so the permissions are part of the mechanism rather
     * than hygiene around it.
     */
    private static void createPrivateDirectory(Path dir) throws Exception {
        if (Files.exists(dir)) {
            return;
        }
        try {
            Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString("rwx------")));
        } catch (UnsupportedOperationException notPosix) {
            Files.createDirectories(dir);
        }
    }

    /**
     * Write the private key so only the owner can read it, and say so out loud when the filesystem
     * cannot promise that.
     *
     * <p>{@code CREATE_NEW} with the mode as a file attribute means the key is never briefly
     * world-readable between creation and a chmod. On a filesystem with no POSIX permissions —
     * Windows, which is where this is developed — that guarantee cannot be made, and the honest
     * response is to write the key and tell the operator the protection is the directory ACL's job,
     * not to fall back silently and leave them believing otherwise.
     */
    private static void writePrivateKey(Path keyPath, byte[] pkcs8) throws Exception {
        try {
            FileAttribute<Set<PosixFilePermission>> ownerOnly = PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString("rw-------"));
            try (FileChannel ch = FileChannel.open(keyPath,
                    EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), ownerOnly)) {
                ch.write(ByteBuffer.wrap(pkcs8));
            }
        } catch (UnsupportedOperationException notPosix) {
            Files.write(keyPath, pkcs8);
            // stderr, not stdout: --print-thumbprint's stdout is captured by the gate and a warning
            // mixed into it would be read as part of the thumbprint.
            System.err.println("[BRIDGE] WARN: " + keyPath + " holds the edge's private key and this"
                    + " filesystem does not support POSIX permissions - restrict access to it by ACL");
        }
    }
}
