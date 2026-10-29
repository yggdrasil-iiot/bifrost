package dev.krillin.bifrost.core.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class DsseTest {
    @TempDir Path tmp;
    static final ObjectMapper JSON = new ObjectMapper();
    static final String TYPE = "http://example.com/HelloWorld";
    static final byte[] HELLO = "hello world".getBytes(StandardCharsets.UTF_8);

    /** The PAE of the DSSE v1.0.2 test vector, written out by hand (protocol.md, "Test Vectors"). */
    @Test void paeIsTheSpecVector() {
        assertArrayEquals("DSSEv1 29 http://example.com/HelloWorld 11 hello world".getBytes(StandardCharsets.US_ASCII), Dsse.pae(TYPE, HELLO));
        assertArrayEquals("DSSEv1 0  0 ".getBytes(StandardCharsets.US_ASCII), Dsse.pae("", new byte[0]));
        // Lengths count bytes, not characters, and the body is taken as it is (NUL included).
        assertArrayEquals(concat("DSSEv1 2 é 3 ".getBytes(StandardCharsets.UTF_8), new byte[]{'a', 0, 'b'}),
            Dsse.pae("é", new byte[]{'a', 0, 'b'}));
    }

    /** The vector's own ECDSA P-256 signature verifies over our PAE bytes, so they are the reference's bytes. */
    @Test void specVectorSignatureVerifiesOverOurPae() throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECPoint w = new ECPoint(new BigInteger("46950820868899156662930047687818585632848591499744589407958293238635476079160"),
            new BigInteger("5640078356564379163099075877009565129882514886557779369047442380624545832820"));
        PublicKey key = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, params.getParameterSpec(ECParameterSpec.class)));
        Signature v = Signature.getInstance("SHA256withECDSAinP1363Format");
        v.initVerify(key);
        v.update(Dsse.pae(TYPE, HELLO));
        assertTrue(v.verify(Base64.getDecoder().decode("A3JqsQGtVsJ2O2xqrI5IcnXip5GToJ3F+FnZ+O88SjtR6rDAajabZKciJTfUiHqJPcIAriEGAHTVeCUjW2JIZA==")));
        v.initVerify(key);
        v.update(Dsse.pae(TYPE + "x", HELLO));
        assertFalse(v.verify(Base64.getDecoder().decode("A3JqsQGtVsJ2O2xqrI5IcnXip5GToJ3F+FnZ+O88SjtR6rDAajabZKciJTfUiHqJPcIAriEGAHTVeCUjW2JIZA==")));
    }

    KeyPair alice, bob;
    AuthorizedKeys keys(String... extra) throws Exception {
        Files.createDirectories(tmp.resolve("identity"));
        StringBuilder s = new StringBuilder();
        s.append(JSON.writeValueAsString(new AuthorizedKey("alice", Ed25519Keys.publicKeyB64(alice.getPublic())))).append('\n');
        s.append(JSON.writeValueAsString(new AuthorizedKey("bob", Ed25519Keys.publicKeyB64(bob.getPublic())))).append('\n');
        for (String e : extra) s.append(e).append('\n');
        Files.writeString(tmp.resolve("identity/authorized-keys.jsonl"), s.toString());
        return AuthorizedKeys.load(tmp);
    }
    @BeforeEach void generate() { alice = Ed25519Keys.generate(); bob = Ed25519Keys.generate(); }
    ObjectNode signed(String type, byte[] body, KeyPair... signers) {
        List<Dsse.Signature> sigs = new ArrayList<>();
        String[] ids = {"alice", "bob"};
        for (int i = 0; i < signers.length; i++) sigs.add(new Dsse.Signature(ids[i % 2], Ed25519Keys.sign(Dsse.pae(type, body), signers[i].getPrivate())));
        return Dsse.envelope(type, body, sigs);
    }
    static IdentityException refused(Runnable r) { return assertThrows(IdentityException.class, r::run); }

    @Test void twoDistinctRegisteredKeysVerify() throws Exception {
        AuthorizedKeys k = keys();
        assertArrayEquals(HELLO, Dsse.verify(signed(TYPE, HELLO, alice, bob), TYPE, k, List.of("alice", "bob")));
        // keyid is a hint: swapped keyids still verify, because the keys decide.
        ObjectNode swapped = signed(TYPE, HELLO, alice, bob);
        ((ObjectNode) swapped.path("signatures").get(0)).put("keyid", "bob");
        ((ObjectNode) swapped.path("signatures").get(1)).put("keyid", "alice");
        assertArrayEquals(HELLO, Dsse.verify(swapped, TYPE, k, List.of("alice", "bob")));
        // The envelope spec allows URL-safe Base64.
        ObjectNode urlSafe = signed(TYPE, new byte[]{(byte) 0xfb, (byte) 0xff}, alice, bob);
        urlSafe.put("payload", Base64.getUrlEncoder().encodeToString(new byte[]{(byte) 0xfb, (byte) 0xff}));
        assertArrayEquals(new byte[]{(byte) 0xfb, (byte) 0xff}, Dsse.verify(urlSafe, TYPE, k, List.of("alice", "bob")));
    }

    @Test void whatTheEnvelopeMustRefuse() throws Exception {
        AuthorizedKeys k = keys();
        List<String> both = List.of("alice", "bob");
        assertEquals("identity.dsse.type", refused(() -> Dsse.verify(signed(TYPE, HELLO, alice, bob), TYPE + "x", k, both)).rule());
        ObjectNode type = signed(TYPE, HELLO, alice, bob);
        type.put("payloadType", TYPE + "x");
        assertEquals("identity.dsse.signature", refused(() -> Dsse.verify(type, TYPE + "x", k, both)).rule());
        ObjectNode body = signed(TYPE, HELLO, alice, bob);
        body.put("payload", Base64.getEncoder().encodeToString("hello worle".getBytes(StandardCharsets.UTF_8)));
        assertEquals("identity.dsse.signature", refused(() -> Dsse.verify(body, TYPE, k, both)).rule());
        assertEquals("identity.dsse.signature", refused(() -> Dsse.verify(signed(TYPE, HELLO, alice), TYPE, k, both)).rule());
        assertEquals("identity.dsse.signature", refused(() -> Dsse.verify(signed(TYPE, HELLO, alice, alice), TYPE, k, both)).rule());
        KeyPair stranger = Ed25519Keys.generate();
        assertEquals("identity.dsse.signature", refused(() -> Dsse.verify(signed(TYPE, HELLO, alice, stranger), TYPE, k, both)).rule());
        ObjectNode shape = signed(TYPE, HELLO, alice, bob);
        shape.remove("signatures");
        assertEquals("identity.dsse.shape", refused(() -> Dsse.verify(shape, TYPE, k, both)).rule());
        ObjectNode garbage = signed(TYPE, HELLO, alice, bob);
        garbage.put("payload", "%%%");
        assertEquals("identity.dsse.base64", refused(() -> Dsse.verify(garbage, TYPE, k, both)).rule());
    }

    @Test void twoPrincipalsOnOneKeyAreOne() throws Exception {
        AuthorizedKeys k = keys(JSON.writeValueAsString(new AuthorizedKey("carol", Ed25519Keys.publicKeyB64(alice.getPublic()))));
        assertEquals("identity.four-eyes.same-key", refused(() -> Dsse.verify(signed(TYPE, HELLO, alice, alice), TYPE, k, List.of("alice", "carol"))).rule());
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] c = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}
