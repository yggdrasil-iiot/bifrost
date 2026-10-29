package dev.krillin.bifrost.core.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.*;

/** DSSE v1.0.2 envelopes (github.com/secure-systems-lab/dsse) signed with the registered Ed25519 keys.
 *  A signature covers PAE(payloadType, payload), never a re-serialization, and a verifier hands on the payload
 *  bytes it verified. keyid names the principal, but it is an unauthenticated hint: a signature counts for a
 *  principal only when it verifies under one of that principal's registered keys, and two principals count as
 *  two only when they resolve to two different keys -- the same four-eyes rule as the approval receipt. */
public final class Dsse {
    public static final String IN_TOTO = "application/vnd.in-toto+json";
    private static final ObjectMapper JSON = new ObjectMapper();
    private Dsse() {}

    public record Signature(String keyid, String sig) {}

    /** PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body, LEN in ASCII decimal bytes. */
    public static byte[] pae(String type, byte[] body) {
        byte[] t = type.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(("DSSEv1 " + t.length + " ").getBytes(StandardCharsets.US_ASCII));
        out.writeBytes(t);
        out.writeBytes((" " + body.length + " ").getBytes(StandardCharsets.US_ASCII));
        out.writeBytes(body);
        return out.toByteArray();
    }

    public static ObjectNode envelope(String type, byte[] body, List<Signature> signatures) {
        ObjectNode e = JSON.createObjectNode();
        e.put("payload", Base64.getEncoder().encodeToString(body));
        e.put("payloadType", type);
        ArrayNode sigs = e.putArray("signatures");
        for (Signature s : signatures) sigs.addObject().put("keyid", s.keyid()).put("sig", s.sig());
        return e;
    }

    /** Verifies that every principal signed PAE(type, payload) with a distinct registered key; returns the
     *  verified payload bytes. Any shortfall is an IdentityException. */
    public static byte[] verify(JsonNode envelope, String expectedType, AuthorizedKeys keys, List<String> principals) {
        if (!envelope.path("payloadType").isTextual() || !envelope.path("payload").isTextual() || !envelope.path("signatures").isArray())
            throw new IdentityException("identity.dsse.shape", "not a DSSE envelope");
        String type = envelope.path("payloadType").asText();
        if (!type.equals(expectedType))
            throw new IdentityException("identity.dsse.type", "payloadType " + type + ", expected " + expectedType);
        byte[] body = decode(envelope.path("payload").asText());
        byte[] pae = pae(type, body);
        List<PublicKey> used = new ArrayList<>();
        for (String principal : principals) {
            Optional<PublicKey> key = Optional.empty();
            for (JsonNode s : envelope.path("signatures")) {
                if (!s.path("sig").isTextual()) continue;
                String sig;
                try { sig = Base64.getEncoder().encodeToString(decode(s.path("sig").asText())); }
                catch (IdentityException e) { continue; }
                key = keys.verifying(principal, pae, sig);
                if (key.isPresent()) break;
            }
            if (key.isEmpty())
                throw new IdentityException("identity.dsse.signature", "no signature verifies for '" + principal + "'");
            for (PublicKey k : used)
                if (Arrays.equals(k.getEncoded(), key.get().getEncoded()))
                    throw new IdentityException("identity.four-eyes.same-key", "'" + principal + "' resolves to a key already counted");
            used.add(key.get());
        }
        return body;
    }

    /** The envelope spec allows standard or URL-safe Base64. */
    static byte[] decode(String b64) {
        try { return Base64.getDecoder().decode(b64); }
        catch (IllegalArgumentException e) {
            try { return Base64.getUrlDecoder().decode(b64); }
            catch (IllegalArgumentException f) { throw new IdentityException("identity.dsse.base64", "not Base64"); }
        }
    }
}
