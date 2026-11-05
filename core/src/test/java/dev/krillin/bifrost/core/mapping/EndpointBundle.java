package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.List;
import java.util.function.Consumer;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;

/** Edits a copy of the vor-read bundle's endpoint and re-pins proposal.json and submission.json, so only the rule under
 *  test fails. */
public final class EndpointBundle {
    public static final List<String> LINKS = List.of("command-bindings/mixer1-set-temperature.json", "command-bindings/mixer2-set-temperature.json");
    public static final String URI = "urn:bifrost:opcua:sim-server";

    private EndpointBundle() {}

    /** A certificate from core's test resources: the fixture's own, or one under server-certificates/. */
    public static byte[] der(String name) throws Exception {
        String path = name.equals("sim") ? "/mapping-fixtures/vor-read/data/server-certificate-sim.der" : "/server-certificates/" + name + ".der";
        return Files.readAllBytes(Path.of(EndpointBundle.class.getResource(path).toURI()));
    }

    /** Add a server-certificate evidence artifact for these bytes, listed in the proposal. */
    public static void addCertificate(Path bundle, String id, byte[] der) throws Exception {
        String data = "data/" + id + ".der", evidence = "evidence/" + id + ".json";
        Files.write(bundle.resolve(data), der);
        ObjectNode ev = (ObjectNode) read(bundle.resolve("evidence/server-certificate-sim.json")).deepCopy();
        ev.put("id", id);
        ((ObjectNode) ev.path("file")).put("path", data).put("sha256", sha(der));
        Files.write(bundle.resolve(evidence), bytes(ev));
        ObjectNode p = (ObjectNode) read(bundle.resolve("proposal.json"));
        ((ArrayNode) p.path("files")).addObject().put("path", evidence).put("kind", "evidence-artifact").put("id", id).put("version", "1.0.0").put("sha256", "");
        Files.write(bundle.resolve("proposal.json"), bytes(p));
        repin(bundle);
    }

    /** The endpointRef entry naming one certificate artifact. */
    public static ObjectNode entry(String id, byte[] der) {
        ObjectNode e = object().put("thumbprintSha1", ServerCertificates.sha1(der));
        e.putObject("certificateRef").put("id", id).put("version", "1.0.0");
        return e;
    }

    /** Edit both links' endpointRef. */
    public static void endpoint(Path bundle, Consumer<ObjectNode> edit) throws Exception {
        for (String l : LINKS) {
            ObjectNode d = (ObjectNode) read(bundle.resolve(l));
            edit.accept((ObjectNode) d.path("endpointRef"));
            Files.write(bundle.resolve(l), bytes(d));
        }
        repin(bundle);
    }

    /** The bundle as contract 2.25.0 wrote it: links without endpointRef and no certificate artifact. */
    public static void legacy(Path bundle) throws Exception {
        for (String l : LINKS) {
            ObjectNode d = (ObjectNode) read(bundle.resolve(l));
            d.put("schemaVersion", "2.25.0").remove("endpointRef");
            Files.write(bundle.resolve(l), bytes(d));
        }
        ObjectNode p = (ObjectNode) read(bundle.resolve("proposal.json"));
        p.put("schemaVersion", "2.25.0");
        for (Iterator<JsonNode> it = p.path("files").iterator(); it.hasNext(); ) {
            JsonNode e = it.next();
            if (text(e, "id").startsWith(ServerCertificates.ID_PREFIX)) {
                JsonNode ev = read(bundle.resolve(text(e, "path")));
                Files.delete(bundle.resolve(text(ev.path("file"), "path")));
                Files.delete(bundle.resolve(text(e, "path")));
                it.remove();
            }
        }
        Files.write(bundle.resolve("proposal.json"), bytes(p));
        repin(bundle);
    }

    /** Re-pin every proposal entry, then the submission's proposal digest. */
    public static void repin(Path bundle) throws Exception {
        ObjectNode p = (ObjectNode) read(bundle.resolve("proposal.json"));
        for (JsonNode e : p.path("files")) ((ObjectNode) e).put("sha256", sha(bundle.resolve(text(e, "path"))));
        Files.write(bundle.resolve("proposal.json"), bytes(p));
        ObjectNode s = (ObjectNode) read(bundle.resolve("submission.json"));
        String digest = sha(bundle.resolve("proposal.json"));
        s.put("proposalSha256", digest).put("workspaceSha256", digest);
        Files.write(bundle.resolve("submission.json"), bytes(s));
    }
}
