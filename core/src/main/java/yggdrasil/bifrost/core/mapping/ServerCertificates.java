package yggdrasil.bifrost.core.mapping;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;

/** An OPC UA server certificate as contract 2.26.0 names it: the DER bytes, their SHA-1 thumbprint (the value OPC UA trust
 *  lists show) and the one subjectAltName URI, which OPC UA makes the server's ApplicationUri. The publish check, approval
 *  and Heimdall all derive both values from the bytes rather than trusting what a document says about them. */
public final class ServerCertificates {
    public static final String MEDIA_TYPE = "application/pkix-cert";
    public static final String ID_PREFIX = "server-certificate-";
    private static final int SAN_URI = 6;

    /** The two derived values of one certificate. */
    public record Parsed(String thumbprintSha1, String applicationUri) {}

    private ServerCertificates() {}

    /** Parse DER bytes: refused "certificate" when they are not exactly one X.509 certificate, "san-uri" unless the
     *  certificate carries exactly one subjectAltName URI. */
    public static Parsed parse(byte[] der) {
        X509Certificate c;
        try {
            Collection<? extends java.security.cert.Certificate> all = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(der));
            if (all.size() != 1 || !(all.iterator().next() instanceof X509Certificate x) || !java.util.Arrays.equals(x.getEncoded(), der))
                throw new IllegalArgumentException("certificate");
            c = x;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("certificate");
        }
        List<String> uris = new ArrayList<>();
        try {
            Collection<List<?>> san = c.getSubjectAlternativeNames();
            if (san != null) for (List<?> n : san) if (n.size() == 2 && Integer.valueOf(SAN_URI).equals(n.get(0))) uris.add(String.valueOf(n.get(1)));
        } catch (Exception e) {
            throw new IllegalArgumentException("san-uri");
        }
        if (uris.size() != 1) throw new IllegalArgumentException("san-uri");
        return new Parsed(sha1(der), uris.get(0));
    }

    /** Lowercase hex SHA-1 of the bytes. */
    public static String sha1(byte[] der) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-1").digest(der));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
