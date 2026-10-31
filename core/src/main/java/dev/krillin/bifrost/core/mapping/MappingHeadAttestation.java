package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;

/** Freshness of a stream head under the TUF rules (theupdateframework.io, spec 1.0.x): a version that only goes
 *  up and an expiry. heads/<stream>.json stays {id,version,sha256} byte for byte; the two numbers live in an
 *  in-toto Statement v1 in a DSSE envelope at mappings/head-attestations/<stream>.dsse.json, signed by a PUBLISH
 *  holder and an APPROVE holder on the stream. The subject is the head file and the release.json it names, by the
 *  SHA-256 of their raw bytes. The highest version reached is kept in an AnchorStore outside mappings/, so a
 *  restored copy of mappings/ is caught as a rollback. */
final class MappingHeadAttestation {
    static final String STATEMENT = "https://in-toto.io/Statement/v1";
    static final String PREDICATE = "https://github.com/yggdrasil-iiot/bifrost/attestation/mapping-head/v1";
    static final Set<String> CAUSES = Set.of("publish", "renew", "migrate");
    private static final Set<String> FIELDS = Set.of("streamId", "headVersion", "expires", "signedAt", "cause",
        "release", "previous", "approvalId", "publishedBy", "approvedBy");
    private MappingHeadAttestation() {}

    static String anchorTarget(String stream) { return "mapping-head-" + stream; }
    static String releasePath(JsonNode head) { return "releases/" + text(head, "id") + "/" + text(head, "version") + "/release.json"; }

    record Head(String stream, JsonNode head, byte[] headBytes) {}

    static byte[] statement(Head h, long headVersion, Instant signedAt, Instant expires, String cause, JsonNode previous,
                            String approvalId, String publishedBy, String approvedBy) throws Exception {
        ObjectNode s = object();
        s.put("_type", STATEMENT);
        ArrayNode subject = s.putArray("subject");
        subject.add(object().put("name", "heads/" + h.stream() + ".json").set("digest", object().put("sha256", sha(h.headBytes()))));
        subject.add(object().put("name", releasePath(h.head())).set("digest", object().put("sha256", text(h.head(), "sha256"))));
        s.put("predicateType", PREDICATE);
        ObjectNode p = s.putObject("predicate");
        p.put("streamId", h.stream()).put("headVersion", headVersion).put("expires", expires.toString())
            .put("signedAt", signedAt.toString()).put("cause", cause).put("approvalId", approvalId)
            .put("publishedBy", publishedBy).put("approvedBy", approvedBy);
        p.set("release", h.head().deepCopy());
        p.set("previous", previous == null ? JSON.nullNode() : previous.deepCopy());
        return bytes(s);
    }

    /** The predicate of a signed statement, after checking it describes exactly this head and its release. */
    static JsonNode matches(JsonNode statement, Head h, JsonNode release) throws Exception {
        require(statement.size() == 4 && text(statement, "_type").equals(STATEMENT)
            && text(statement, "predicateType").equals(PREDICATE), "mapping.head-attestation-statement");
        JsonNode p = statement.path("predicate");
        Set<String> names = new HashSet<>();p.fieldNames().forEachRemaining(names::add);
        require(names.equals(FIELDS) && text(p, "streamId").equals(h.stream()) && p.path("headVersion").canConvertToLong()
            && p.path("headVersion").isIntegralNumber() && p.path("headVersion").asLong() >= 1 && CAUSES.contains(text(p, "cause"))
            && !text(p, "publishedBy").equals(text(p, "approvedBy")), "mapping.head-attestation-statement");
        Instant signed = instant(p, "signedAt"), expires = instant(p, "expires");
        require(signed.isBefore(expires), "mapping.head-attestation-statement");
        JsonNode previous = p.path("previous");
        // Version 1 starts the chain; every later version names the one it replaced.
        require(previous.isNull() == (p.path("headVersion").asLong() == 1), "mapping.head-attestation-statement");
        require(previous.isNull() || previous.isObject() && previous.size() == 2 && previous.path("headVersion").isIntegralNumber()
            && previous.path("headVersion").asLong() == p.path("headVersion").asLong() - 1 && previous.path("release").isObject(), "mapping.head-attestation-statement");
        require(text(p, "approvalId").equals(text(release.path("approval").path("payload"), "approvalId")), "mapping.head-attestation-statement");
        require(p.path("release").equals(h.head()), "mapping.head-attestation-subject");
        JsonNode subject = statement.path("subject");
        require(subject.isArray() && subject.size() == 2, "mapping.head-attestation-subject");
        String[][] expected = {{"heads/" + h.stream() + ".json", sha(h.headBytes())}, {releasePath(h.head()), text(h.head(), "sha256")}};
        for (int i = 0; i < 2; i++) {
            JsonNode s = subject.get(i);
            require(s.size() == 2 && s.path("digest").size() == 1 && text(s, "name").equals(expected[i][0])
                && text(s.path("digest"), "sha256").equals(expected[i][1]), "mapping.head-attestation-subject");
        }
        return p;
    }

    static Instant instant(JsonNode p, String field) {
        String v = text(p, field);
        require(v.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"), "mapping.head-attestation-statement");
        try { return Instant.parse(v); } catch (RuntimeException e) { throw new IllegalArgumentException("mapping.head-attestation-statement"); }
    }
}
