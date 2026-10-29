package dev.krillin.bifrost.core.schema;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.krillin.bifrost.core.activation.*;
import dev.krillin.bifrost.core.identity.*;
import java.io.IOException;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;

/** A recipe publication as an in-toto Statement v1 (github.com/in-toto/attestation) whose predicate is SLSA
 *  Provenance v1 (slsa.dev/provenance/v1), in a DSSE envelope: recipe/<ref>/<version>/manifest.dsse.json, written
 *  by a signed publish before the canonical and manifest.json. One publisher signs; the claim is only "this
 *  principal published these two files, generated from this git commit". Review stays in git and four-eyes stays at
 *  activation. The subject is the raw-byte SHA-256 of recipe-setpoints.yaml and manifest.json, so the manifest's
 *  seven fields are bound by digest and manifest.json is not changed by a byte. No SLSA level is claimed. */
public final class RecipeAttestation {
    public static final String FILE = "manifest.dsse.json";
    static final String STATEMENT = "https://in-toto.io/Statement/v1";
    static final String PREDICATE = "https://slsa.dev/provenance/v1";
    static final String BUILD_TYPE = "https://github.com/yggdrasil-iiot/bifrost/blob/main/docs/RECIPE-PUBLICATION.md#build-type-v1";
    static final String BUILDER = "https://github.com/yggdrasil-iiot/bifrost/gates/provenance-publish";
    static final String TARGET = "recipe-publication";
    static final String CANONICAL = "recipe-setpoints.yaml", MANIFEST = "manifest.json";
    private static final ObjectMapper JSON = new ObjectMapper();
    private RecipeAttestation() {}

    /** A coded refusal; the CLI exits 1 on it, as it does for a dirty source. */
    public static final class Refused extends RuntimeException { public Refused(String code) { super(code); } }
    static void require(boolean ok, String code) { if (!ok) throw new Refused(code); }

    /** The publisher's key must be bound and in its window, and the policy must grant it PUBLISH on this recipe. */
    static void admit(Path registry, KeyFileSigner signer, String kind, String ref) {
        List<Violation> v = signer.preflight();
        require(v.isEmpty(), v.isEmpty() ? "" : v.get(0).rule());
        authorized(registry, signer.principal(), kind, ref);
    }

    private static void authorized(Path registry, String principal, String kind, String ref) {
        require(new ActivationAuthorizer().authorize(ActivationPolicyStore.load(registry), principal,
                ActivationAction.PUBLISH, TARGET, kind, ref).allowed(), "recipe.publish-denied");
    }

    static byte[] statement(RecipeManifest m, String manifestSha, String publishedBy) throws IOException {
        ObjectNode s = JSON.createObjectNode();
        s.put("_type", STATEMENT);
        var subject = s.putArray("subject");
        subject.addObject().put("name", CANONICAL).putObject("digest").put("sha256", m.contentSha256());
        subject.addObject().put("name", MANIFEST).putObject("digest").put("sha256", manifestSha);
        s.put("predicateType", PREDICATE);
        ObjectNode build = s.putObject("predicate").putObject("buildDefinition");
        build.put("buildType", BUILD_TYPE);
        build.putObject("externalParameters").put("kind", m.kind()).put("ref", m.ref()).put("version", m.version())
                .put("sourcePath", m.sourcePath()).put("publishedBy", publishedBy);
        build.putArray("resolvedDependencies").addObject().put("name", m.sourcePath())
                .putObject("digest").put("gitCommit", m.defRef());
        ObjectNode run = ((ObjectNode) s.get("predicate")).putObject("runDetails");
        run.putObject("builder").put("id", BUILDER);
        run.putObject("metadata").put("finishedOn", timestamp(m.publishedAt()));
        return JSON.writeValueAsBytes(s);
    }

    /** SLSA timestamps are UTC to the second; publishedAt keeps its milliseconds in manifest.json. */
    static String timestamp(long millis) {
        return DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(millis).truncatedTo(ChronoUnit.SECONDS));
    }

    static byte[] envelope(byte[] statement, KeyFileSigner signer) throws IOException {
        String sig = signer.signRaw(Dsse.pae(Dsse.IN_TOTO, statement));
        return JSON.writeValueAsBytes(Dsse.envelope(Dsse.IN_TOTO, statement, List.of(new Dsse.Signature(signer.principal(), sig))));
    }

    /** Verifies recipe/<ref>/<version>: the publisher named in the statement signed it with a registered key, the
     *  policy grants that publisher PUBLISH now, the subject is exactly the two files on disk, and the predicate
     *  restates manifest.json. Returns the verified statement. */
    public static JsonNode verify(Path registry, String ref, String version) throws IOException {
        Path dir = registry.resolve("recipe").resolve(ref).resolve(version);
        Path canonical = dir.resolve(CANONICAL), manifestFile = dir.resolve(MANIFEST), file = dir.resolve(FILE);
        require(Files.isRegularFile(canonical) && Files.isRegularFile(manifestFile), "recipe.unresolved");
        require(Files.isRegularFile(file), "recipe.attestation-missing");
        return verify(registry, ref, version, Files.readAllBytes(canonical), Files.readAllBytes(manifestFile), Files.readAllBytes(file));
    }

    /** The same checks over bytes the caller has already read, so a caller that also hashes and parses those bytes
     *  checks one snapshot rather than files that may change between two reads. */
    public static JsonNode verify(Path registry, String ref, String version, byte[] canonicalBytes, byte[] manifestBytes,
                                  byte[] envelopeBytes) throws IOException {
        JsonNode env;
        try { env = JSON.readTree(envelopeBytes); } catch (Exception e) { throw new Refused("recipe.attestation-signature:identity.dsse.shape"); }
        // The publisher is read from the unverified payload only to know whose key to try; it counts once that key verifies.
        String publisher;
        try { publisher = JSON.readTree(Base64.getDecoder().decode(env.path("payload").asText()))
                .path("predicate").path("buildDefinition").path("externalParameters").path("publishedBy").asText(); }
        catch (Exception e) { publisher = ""; }
        byte[] body;
        try { body = Dsse.verify(env, Dsse.IN_TOTO, AuthorizedKeys.load(registry), List.of(publisher)); }
        catch (IdentityException e) { throw new Refused("recipe.attestation-signature:" + e.rule()); }
        JsonNode s = JSON.readTree(body);
        RecipeManifest m = JsonMapperFactory.create().readValue(manifestBytes, RecipeManifest.class);
        lineEndings(s, canonicalBytes, manifestBytes);
        matches(s, m, ref, version, sha(canonicalBytes), sha(manifestBytes));
        authorized(registry, publisher, m.kind(), ref);
        return s;
    }

    /** Refuses with its own code when the only difference from the signed subject is a line-ending conversion. */
    static void lineEndings(JsonNode s, byte[] canonicalBytes, byte[] manifestBytes) {
        Map<String, String> signed = new HashMap<>();
        for (JsonNode e : s.path("subject")) signed.put(e.path("name").asText(), e.path("digest").path("sha256").asText());
        String canonicalSha = signed.get(CANONICAL), manifestSha = signed.get(MANIFEST);
        if (canonicalSha == null || manifestSha == null) return;
        boolean canonicalConverted = LineEndings.explainMismatch(canonicalBytes, canonicalSha);
        boolean manifestConverted = LineEndings.explainMismatch(manifestBytes, manifestSha);
        require(!((canonicalConverted || sha(canonicalBytes).equals(canonicalSha))
                && (manifestConverted || sha(manifestBytes).equals(manifestSha))
                && (canonicalConverted || manifestConverted)), "recipe.attestation-subject:line-endings");
    }

    static void matches(JsonNode s, RecipeManifest m, String ref, String version, String canonicalSha, String manifestSha) {
        JsonNode build = s.path("predicate").path("buildDefinition"), run = s.path("predicate").path("runDetails");
        require(STATEMENT.equals(s.path("_type").asText()) && PREDICATE.equals(s.path("predicateType").asText())
                && BUILD_TYPE.equals(build.path("buildType").asText())
                && BUILDER.equals(run.path("builder").path("id").asText()), "recipe.attestation-statement");
        Set<String> subject = new HashSet<>();
        for (JsonNode e : s.path("subject")) {
            require(e.size() == 2 && e.path("digest").size() == 1 && e.path("digest").path("sha256").isTextual(), "recipe.attestation-subject");
            require(subject.add(e.path("name").asText() + "\t" + e.path("digest").path("sha256").asText()), "recipe.attestation-subject");
        }
        require(subject.equals(Set.of(CANONICAL + "\t" + canonicalSha, MANIFEST + "\t" + manifestSha)), "recipe.attestation-subject");
        JsonNode p = build.path("externalParameters"), deps = build.path("resolvedDependencies");
        require(m.contentSha256().equals(canonicalSha) && m.ref().equals(ref) && m.version().equals(version)
                && m.kind().equals(p.path("kind").asText()) && ref.equals(p.path("ref").asText())
                && version.equals(p.path("version").asText()) && m.sourcePath().equals(p.path("sourcePath").asText())
                && deps.size() == 1 && m.sourcePath().equals(deps.get(0).path("name").asText())
                && m.defRef().equals(deps.get(0).path("digest").path("gitCommit").asText())
                && timestamp(m.publishedAt()).equals(run.path("metadata").path("finishedOn").asText()), "recipe.attestation-predicate");
    }

    static String sha(byte[] b) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
}
