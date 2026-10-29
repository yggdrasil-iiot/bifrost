package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;

/** The four-eyes approval of a mapping bundle as an in-toto Statement v1 (github.com/in-toto/attestation) in a
 *  DSSE envelope: mappings/attestations/<approvalId>.dsse.json, written by approve beside the receipt and signed by
 *  the same two keys at the same moment. The subject is the bundle the two principals reviewed -- every file, by
 *  the raw-byte SHA-256 under the name release.json will give it ("payload/<path>") -- so an outside verifier
 *  matches a published release by digest alone, without reproducing Bifrost's own serialization. The predicate is
 *  the receipt's payload, field for field. Receipts, releases and heads are not changed by a byte. */
final class MappingAttestation {
    static final String STATEMENT = "https://in-toto.io/Statement/v1";
    static final String PREDICATE = "https://github.com/yggdrasil-iiot/bifrost/attestation/mapping-approval/v1";
    private MappingAttestation() {}

    static byte[] statement(Map<String,String> files, JsonNode payload) throws Exception {
        ObjectNode s = object();
        s.put("_type", STATEMENT);
        ArrayNode subject = s.putArray("subject");
        for (var f : new TreeMap<>(files).entrySet()) {
            ObjectNode digest = object().put("sha256", f.getValue());
            subject.add(object().put("name", "payload/" + f.getKey()).set("digest", digest));
        }
        s.put("predicateType", PREDICATE);
        s.set("predicate", payload.deepCopy());
        return bytes(s);
    }

    /** Checks a verified statement against the release it should describe: the receipt payload as predicate, and
     *  the subject equal (both ways) to the release's files[]. */
    static void matches(JsonNode statement, JsonNode release) {
        require(text(statement, "_type").equals(STATEMENT) && text(statement, "predicateType").equals(PREDICATE)
            && statement.path("predicate").equals(release.path("approval").path("payload")), "mapping.attestation-statement");
        Set<String> subject = new HashSet<>(), files = new HashSet<>();
        for (JsonNode s : statement.path("subject")) {
            require(s.size() == 2 && s.path("digest").size() == 1 && s.path("digest").path("sha256").isTextual(), "mapping.attestation-subject");
            require(subject.add(text(s, "name") + "\t" + text(s.path("digest"), "sha256")), "mapping.attestation-subject");
        }
        for (JsonNode f : release.path("files")) files.add(text(f, "path") + "\t" + text(f, "sha256"));
        require(subject.equals(files), "mapping.attestation-subject");
    }
}
