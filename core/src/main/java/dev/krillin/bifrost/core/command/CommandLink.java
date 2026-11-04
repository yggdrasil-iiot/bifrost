package dev.krillin.bifrost.core.command;

import com.fasterxml.jackson.databind.JsonNode;
import dev.krillin.bifrost.core.mapping.ReadBindingProfile;
import dev.krillin.bifrost.core.mapping.ServerCertificates;
import java.nio.file.*;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;

/** The published command binding (mapping contract 2.25.0 or 2.26.0) a proposal must name through its key: the release's one
 *  link whose read binding's device is the proposal's target.device and whose Method is the proposal's methodNodeId. The link,
 *  its read binding (Vor profile 0.1.0), the mapping set that binding names and the server certificates its endpointRef
 *  names are read from the pinned release's bytes, each checked against the digest release.json records for it. Only a
 *  2.26.0 link names the server it may call; a 2.25.0 link is still resolved, so it can be read and reported, and is
 *  refused command.link.endpoint (missing) wherever a command would be authorized by it. */
public final class CommandLink {
    public static final String KIND = "command-binding";

    /** One resolved link, with the read binding it points at and where that binding lives in the release. */
    public record Link(String id, String version, String group, String edge, String objectNodeId, String methodNodeId,
                       String inputName, String inputType, String unit, ReadBindingProfile binding, String bindingPath,
                       String bindingSha256, String mappingSetPath, Endpoint endpoint) {
        /** The server this link authorizes, or a command.link.endpoint refusal when the link names none. */
        public Endpoint requireEndpoint() {
            if (endpoint == null) throw new Refusal("command.link.endpoint", "missing");
            return endpoint;
        }
    }

    /** The OPC UA server a 2.26.0 link may call: its ApplicationUri and the certificates (DER, from the release) it may
     *  present. More than one certificate is a rotation overlap. */
    public record Endpoint(String applicationUri, List<Certificate> certificates) {
        public record Certificate(String thumbprintSha1, byte[] der) {}

        /** Why an authenticated session is not this endpoint, or null when it is: its server certificate must be byte-equal
         *  to a listed one (whose subjectAltName URI is applicationUri, checked at resolution) and the endpoint description's
         *  server ApplicationUri must be applicationUri too. */
        public String refusal(byte[] serverCertificate, String serverApplicationUri) {
            boolean listed = false;
            for (Certificate c : certificates) listed |= serverCertificate != null && Arrays.equals(c.der(), serverCertificate);
            if (!listed) return "certificate " + (serverCertificate == null ? "none" : ServerCertificates.sha1(serverCertificate));
            if (!applicationUri.equals(serverApplicationUri)) return "server.applicationUri " + serverApplicationUri;
            return null;
        }
    }

    private static final Set<String> VERSIONS = Set.of("2.25.0", "2.26.0");

    /** A refusal whose message is the reason code and whose detail names the field that differs. */
    public static final class Refusal extends IllegalArgumentException {
        private final String detail;
        Refusal(String code, String detail) {super(code); this.detail = detail;}
        public String detail() {return detail;}
    }

    /** A published release as the verifiers read it: its directory, its root under mappings/, and release.json's files. */
    record Release(Path dir, String root, Map<String, String> files) {
        static Release of(Path registry, JsonNode head) throws Exception {
            String root = "releases/" + text(head, "id") + "/" + text(head, "version");
            Path dir = registry.resolve("mappings/" + root);
            Map<String, String> files = new HashMap<>();
            for (JsonNode f : JSON.readTree(Files.readAllBytes(dir.resolve("release.json"))).path("files")) files.put(text(f, "path"), text(f, "sha256"));
            return new Release(dir, root, files);
        }
        /** A file of the release by its release path, refused with code when it is unlisted or its bytes differ. */
        byte[] bytes(String path, String code, String detail) throws Exception {
            if (!files.containsKey(path)) throw new Refusal(code, detail);
            byte[] b = Files.readAllBytes(safe(dir, path));
            if (!sha(b).equals(files.get(path))) throw new Refusal(code, detail);
            return b;
        }
        JsonNode json(String path, String code, String detail) throws Exception {return JSON.readTree(bytes(path, code, detail));}
    }

    private CommandLink() {}

    /** The one link for (target.device, methodNodeId): none is command.link.missing, more than one command.link.ambiguous. */
    static Link resolve(Release r, CommandProposal.Proposal p) throws Exception {
        JsonNode listing = r.json("payload/proposal.json", "command.link.missing", "release");
        Map<String, JsonNode> evidence = new HashMap<>();
        Map<String, String> sets = new HashMap<>();
        List<JsonNode> links = new ArrayList<>();
        for (JsonNode e : listing.path("files")) {
            String key = text(e, "id") + "@" + text(e, "version");
            switch (text(e, "kind")) {
                case "evidence-artifact" -> evidence.put(key, r.json("payload/" + text(e, "path"), "command.link.mismatch", "release-file"));
                case "mapping-set" -> sets.put(key, "payload/" + text(e, "path"));
                case KIND -> links.add(r.json("payload/" + text(e, "path"), "command.link.mismatch", "release-file"));
                default -> {}
            }
        }
        List<Link> hits = new ArrayList<>();
        List<JsonNode> hitDocs = new ArrayList<>();
        for (JsonNode l : links) {
            JsonNode rb = l.path("readBindingRef"), ev = evidence.get(text(rb, "id") + "@" + text(rb, "version"));
            if (ev == null) throw new Refusal("command.link.mismatch", "readBindingRef");
            String data = "payload/" + text(ev.path("file"), "path");
            if (!text(ev.path("file"), "sha256").equals(r.files().get(data))) throw new Refusal("command.link.mismatch", "binding.file");
            ReadBindingProfile b;
            try {b = ReadBindingProfile.parse(r.bytes(data, "command.link.mismatch", "binding.file"), "command.link.mismatch");}
            catch (Refusal x) {throw x;} catch (IllegalArgumentException x) {throw new Refusal("command.link.mismatch", "binding.profile");}
            JsonNode m = l.path("method"), in = m.path("inputs");
            if (!b.device().equals(p.target().device()) || !text(m, "methodNodeId").equals(p.methodNodeId())) continue;
            String set = sets.get(b.mappingSetId() + "@" + b.mappingSetVersion());
            if (set == null || in.size() != 1) throw new Refusal("command.link.mismatch", set == null ? "binding.mappingSetRef" : "method.inputs");
            hits.add(new Link(text(l, "id"), text(l, "version"), text(l.path("command"), "group"), text(l.path("command"), "edge"),
                text(m, "objectNodeId"), text(m, "methodNodeId"), text(in.get(0), "name"), text(in.get(0), "type"), text(in.get(0), "unit"),
                b, data, r.files().get(data), set, null));
            hitDocs.add(l);
        }
        if (hits.isEmpty()) throw new Refusal("command.link.missing", "device+methodNodeId");
        if (hits.size() > 1) throw new Refusal("command.link.ambiguous", "device+methodNodeId");
        Link hit = hits.get(0);
        JsonNode doc = hitDocs.get(0);
        String version = text(doc, "schemaVersion");
        if (!VERSIONS.contains(version)) throw new Refusal("command.link.mismatch", "schemaVersion");
        if (version.equals("2.25.0") || !doc.has("endpointRef")) return hit;
        return new Link(hit.id(), hit.version(), hit.group(), hit.edge(), hit.objectNodeId(), hit.methodNodeId(), hit.inputName(),
            hit.inputType(), hit.unit(), hit.binding(), hit.bindingPath(), hit.bindingSha256(), hit.mappingSetPath(),
            endpoint(r, doc.path("endpointRef"), evidence));
    }

    /** The endpointRef's certificates from the release bytes, each re-derived: its SHA-1 is the listed thumbprint and its
     *  one subjectAltName URI is the link's applicationUri. */
    private static Endpoint endpoint(Release r, JsonNode ref, Map<String, JsonNode> evidence) throws Exception {
        String uri = text(ref, "applicationUri");
        if (uri.isEmpty() || ref.path("certificates").isEmpty()) throw new Refusal("command.link.endpoint", "missing");
        List<Endpoint.Certificate> certs = new ArrayList<>();
        for (JsonNode c : ref.path("certificates")) {
            JsonNode cr = c.path("certificateRef"), ev = evidence.get(text(cr, "id") + "@" + text(cr, "version"));
            if (ev == null || !text(ev.path("file"), "mediaType").equals(ServerCertificates.MEDIA_TYPE))
                throw new Refusal("command.link.endpoint", "certificateRef");
            String data = "payload/" + text(ev.path("file"), "path");
            if (!text(ev.path("file"), "sha256").equals(r.files().get(data))) throw new Refusal("command.link.endpoint", "certificateRef");
            byte[] der = r.bytes(data, "command.link.endpoint", "certificateRef");
            ServerCertificates.Parsed parsed;
            try {parsed = ServerCertificates.parse(der);}
            catch (IllegalArgumentException x) {throw new Refusal("command.link.endpoint", "certificate." + x.getMessage());}
            if (!parsed.thumbprintSha1().equals(text(c, "thumbprintSha1"))) throw new Refusal("command.link.endpoint", "thumbprintSha1");
            if (!parsed.applicationUri().equals(uri)) throw new Refusal("command.link.endpoint", "applicationUri");
            certs.add(new Endpoint.Certificate(parsed.thumbprintSha1(), der));
        }
        return new Endpoint(uri, List.copyOf(certs));
    }

    /** The proposal and its evidence say what the link says: the device, the evidence bound to the released read-binding
     *  bytes and fields, the command node, and the Method's signature. The input value is the command policy's to bound. */
    static void match(Release r, Link l, CommandProposal.Proposal p, JsonNode answer) {
        ReadBindingProfile b = l.binding();
        mismatch(b.device().equals(p.target().device()), "device");
        JsonNode eb = answer.path("binding"), src = eb.path("source"), pin = answer.path("pin"), def = eb.path("governedDefinitionRef");
        mismatch(text(src, "sha256").equals(l.bindingSha256()) && text(src, "file").equals("mappings/" + r.root() + "/" + l.bindingPath()), "binding.source");
        for (String[] f : new String[][]{{"group", b.group()}, {"edge", b.edge()}, {"device", b.device()}, {"metric", b.metric()}})
            mismatch(text(eb, f[0]).equals(f[1]), "binding." + f[0]);
        mismatch(text(def, "templateRef").equals(b.templateRef()) && text(def, "version").equals(b.templateVersion()) && text(def, "sha256").equals(b.templateSha256()),
            "binding.governedDefinitionRef");
        mismatch(text(pin, "field_id").equals(b.mappingId()), "pin.field_id");
        mismatch(text(pin, "file").equals(l.mappingSetPath()), "pin.file");
        mismatch(p.target().group().equals(l.group()) && p.target().edge().equals(l.edge()), "command");
        mismatch(p.objectNodeId().equals(l.objectNodeId()), "method.objectNodeId");
        mismatch(p.methodNodeId().equals(l.methodNodeId()), "method.methodNodeId");
        mismatch(p.input().equals(l.inputName()) && l.inputType().equals("Double"), "method.inputs");
    }

    private static void mismatch(boolean ok, String detail) {if (!ok) throw new Refusal("command.link.mismatch", detail);}
}
