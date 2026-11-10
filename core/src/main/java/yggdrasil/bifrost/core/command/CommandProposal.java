package yggdrasil.bifrost.core.command;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import yggdrasil.bifrost.core.acl.*;
import yggdrasil.bifrost.core.activation.*;
import yggdrasil.bifrost.core.identity.*;
import yggdrasil.bifrost.core.mapping.MappingRegistry;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import static yggdrasil.bifrost.core.mapping.MappingJson.*;

/** A governed write proposal: an in-toto Statement v1 in a DSSE envelope, signed first by the proposing agent and then
 *  co-signed by the approver over the same PAE bytes, never a re-serialization. The subjects pin the stream head, the
 *  release it names and the Vor read answer carried as evidence, each by the SHA-256 of its raw bytes; the predicate
 *  names one OPC UA Method call with one Double input and a validity window of at most 15 minutes. Version 2: target.group
 *  and target.edge name the command node, target.device the governed equipment by the Sparkplug device id its data edge
 *  publishes, and the pinned release must carry the one command binding that links that device's read binding to the
 *  Method (CommandLink). A v1 statement is malformed. Approval re-checks everything the agent claimed against this
 *  registry before it signs. Refusals are IllegalArgumentExceptions whose message is the reason code. */
public final class CommandProposal {
    public static final String STATEMENT = "https://in-toto.io/Statement/v1";
    public static final String PREDICATE = "https://github.com/yggdrasil-iiot/bifrost/attestation/command-proposal/v2";
    public static final Duration MAX_WINDOW = Duration.ofMinutes(15);
    /** The activation-policy resource a command grant names; its ref is the stream. */
    public static final String GRANT_TARGET = "command", GRANT_KIND = "method";
    private static final Set<String> FIELDS = Set.of("cmdId", "streamId", "target", "method", "validity", "proposedBy", "approvedBy", "evidence");
    private static final String UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    private static final String INSTANT = "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z";
    private static final String NODE_ID = "nsu=[^;]+;s=.+";
    private CommandProposal() {}

    /** The checked predicate and the exact payload bytes the signatures cover. */
    public record Proposal(byte[] payload, JsonNode statement, String cmdId, String streamId, Target target, String objectNodeId,
                           String methodNodeId, String input, double value, Instant notBefore, Instant notAfter,
                           String proposedBy, String approvedBy, byte[] evidence) {
        String subject(int i) {return text(statement.path("subject").get(i).path("digest"), "sha256");}
    }

    /** The statement's shape, with no registry and no clock: field sets, the window span, the evidence digest. */
    public static Proposal parse(byte[] payload) {
        JsonNode s;
        try {s = JSON.readTree(payload);} catch (Exception e) {throw new IllegalArgumentException("command.malformed");}
        require(s != null && s.isObject() && s.size() == 4 && text(s, "_type").equals(STATEMENT) && text(s, "predicateType").equals(PREDICATE), "command.malformed");
        JsonNode p = s.path("predicate");
        Set<String> names = new HashSet<>();p.fieldNames().forEachRemaining(names::add);
        require(names.equals(FIELDS) && text(p, "cmdId").matches(UUID) && text(p, "streamId").matches("[a-zA-Z0-9._-]+"), "command.malformed");
        JsonNode t = p.path("target");
        require(t.isObject() && t.size() == 3 && nonEmpty(t, "group") && nonEmpty(t, "edge") && nonEmpty(t, "device"), "command.malformed");
        JsonNode m = p.path("method"), inputs = m.path("inputs");
        require(m.isObject() && m.size() == 3 && text(m, "objectNodeId").matches(NODE_ID) && text(m, "methodNodeId").matches(NODE_ID)
            && inputs.isArray() && inputs.size() == 1, "command.malformed");
        JsonNode in = inputs.get(0);
        require(in.isObject() && in.size() == 3 && nonEmpty(in, "name") && text(in, "type").equals("Double") && in.path("value").isNumber()
            && Double.isFinite(in.path("value").asDouble()), "command.malformed");
        require(nonEmpty(p, "proposedBy") && nonEmpty(p, "approvedBy"), "command.malformed");
        require(!text(p, "proposedBy").equals(text(p, "approvedBy")), "identity.four-eyes.same-key");
        JsonNode w = p.path("validity");
        require(w.isObject() && w.size() == 2 && text(w, "notBefore").matches(INSTANT) && text(w, "notAfter").matches(INSTANT), "command.malformed");
        Instant notBefore = instant(w, "notBefore"), notAfter = instant(w, "notAfter");
        require(notBefore.isBefore(notAfter) && Duration.between(notBefore, notAfter).compareTo(MAX_WINDOW) <= 0, "command.window");
        JsonNode ev = p.path("evidence");
        require(ev.isObject() && ev.size() == 2 && text(ev, "mediaType").equals("application/json") && ev.path("base64").isTextual(), "command.malformed");
        byte[] evidence;
        try {evidence = Base64.getDecoder().decode(text(ev, "base64"));} catch (IllegalArgumentException e) {throw new IllegalArgumentException("command.malformed");}
        String stream = text(p, "streamId");
        JsonNode subject = s.path("subject");
        require(subject.isArray() && subject.size() == 3, "command.malformed");
        String[] expected = {"heads/" + stream + ".json", null, "evidence"};
        for (int i = 0; i < 3; i++) {
            JsonNode x = subject.get(i);
            require(x.isObject() && x.size() == 2 && x.path("digest").size() == 1 && text(x.path("digest"), "sha256").matches("[0-9a-f]{64}")
                && (expected[i] == null ? text(x, "name").matches("releases/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+/release\\.json") : text(x, "name").equals(expected[i])), "command.malformed");
        }
        try {require(sha(evidence).equals(text(subject.get(2).path("digest"), "sha256")), "command.evidence.digest");}
        catch (IllegalArgumentException e) {throw e;} catch (Exception e) {throw new IllegalStateException(e);}
        return new Proposal(payload, s, text(p, "cmdId"), stream, new Target(text(t, "group"), text(t, "edge"), text(t, "device")),
            text(m, "objectNodeId"), text(m, "methodNodeId"), text(in, "name"), in.path("value").asDouble(), notBefore, notAfter,
            text(p, "proposedBy"), text(p, "approvedBy"), evidence);
    }

    /** Offline check of a proposal (one signature, the proposer's) or an approved envelope (exactly two: the proposer's and
     *  the approver's, on distinct keys), its shape, and its binding to this registry's current head. */
    public static ObjectNode verify(Path registry, JsonNode envelope, boolean approved, Clock clock) throws Exception {
        require(envelope.path("signatures").isArray() && envelope.path("signatures").size() == (approved ? 2 : 1), "command.signature");
        Proposal p = signed(registry, envelope, approved);
        JsonNode head = bind(registry, p, clock);
        link(registry, p, head);
        return summary(approved ? "command-approved-verification" : "command-proposal-verification", p, head);
    }

    /** Re-checks a proposal as the named approver and, only if every check passes, appends that approver's signature over
     *  the same PAE bytes. Returns the approved envelope and a report. */
    public record Approval(ObjectNode envelope, ObjectNode report) {}

    public static Approval approve(Path registry, JsonNode envelope, String approver, Path approverKey, Path commandPolicy, Clock clock) throws Exception {
        require(envelope.path("signatures").isArray() && envelope.path("signatures").size() == 1, "command.signature");
        Proposal p = signed(registry, envelope, false);
        require(approver.equals(p.approvedBy()), "command.approver.mismatch");
        require(clock.instant().isBefore(p.notAfter()), "command.window");
        ActivationPolicy grants = ActivationPolicyStore.load(registry);
        ActivationAuthorizer authz = new ActivationAuthorizer();
        AuthzDecision proposeGrant = authz.authorize(grants, p.proposedBy(), ActivationAction.PROPOSE_COMMAND, GRANT_TARGET, GRANT_KIND, p.streamId());
        AuthzDecision approveGrant = authz.authorize(grants, approver, ActivationAction.APPROVE_COMMAND, GRANT_TARGET, GRANT_KIND, p.streamId());
        require(proposeGrant.allowed() && approveGrant.allowed(), "command.grant");
        JsonNode head = bind(registry, p, clock);
        CommandLink.Link link = link(registry, p, head);
        CommandPolicy policy = AclMapperFactory.create().readValue(commandPolicy.toFile(), CommandPolicy.class);
        require("deny".equals(policy.defaultEffect()), "command.policy.denied");
        Decision bounds = new CommandAuthorizer().authorize(policy, new CommandRequest(p.target(), p.methodNodeId(), p.value(), "Double", p.proposedBy()));
        require(bounds.allowed(), "command.policy.denied");
        AuthorizedKeys keys = AuthorizedKeys.load(registry);
        KeyFileSigner signer = KeyFileSigner.create(approver, approverKey, keys, clock);
        require(signer.preflight().isEmpty(), "command.signature");
        List<Dsse.Signature> sigs = new ArrayList<>();
        for (JsonNode s : envelope.path("signatures")) sigs.add(new Dsse.Signature(text(s, "keyid"), text(s, "sig")));
        sigs.add(new Dsse.Signature(approver, signer.signRaw(Dsse.pae(Dsse.IN_TOTO, p.payload()))));
        ObjectNode approved = Dsse.envelope(Dsse.IN_TOTO, p.payload(), sigs);
        signed(registry, approved, true);
        ObjectNode report = summary("command-approval", p, head);
        report.put("proposeGrant", proposeGrant.ruleId()).put("approveGrant", approveGrant.ruleId()).put("policyRule", bounds.ruleId());
        ObjectNode binding = report.putObject("commandBinding").put("id", link.id()).put("version", link.version());
        // The server the link authorizes, as the release's certificates say. Approval has no session: this is not a claim
        // about the live server, which Heimdall compares at call time.
        ObjectNode endpoint = binding.putObject("endpoint").put("applicationUri", link.endpoint().applicationUri());
        for (CommandLink.Endpoint.Certificate c : link.endpoint().certificates()) endpoint.withArray("thumbprintsSha1").add(c.thumbprintSha1());
        return new Approval(approved, report);
    }

    /** An approved proposal the edge may act on: admitted at the edge's own clock, with the command binding it resolved and
     *  the live precondition its pinned release names - the OPC UA node behind the link's read binding and that binding's
     *  freshness bound. */
    public record Admitted(Proposal proposal, JsonNode head, CommandLink.Link link, String preconditionNodeId, long maxAgeMs) {}

    /** The edge's admission of an approved envelope, in the order the edge checks: exactly two signatures by the proposer
     *  and the approver on distinct keys, notBefore <= now < notAfter, the head and release this registry serves now, a
     *  usable evidence answer, the command binding for the target, and the precondition that binding's read binding names. Refusals are IllegalArgumentExceptions whose
     *  message is the reason code. */
    public static Admitted admit(Path registry, JsonNode envelope, Clock clock) throws Exception {
        require(envelope != null && envelope.isObject() && envelope.path("signatures").isArray() && envelope.path("signatures").size() == 2, "command.signature");
        Proposal p;
        try {p = signed(registry, envelope, true);}
        catch (IllegalArgumentException e) {
            if (e.getMessage().equals("command.signature") && signedByOther(registry, envelope)) throw new IllegalArgumentException("command.approver.mismatch");
            throw e;
        }
        Instant now = clock.instant();
        require(!now.isBefore(p.notBefore()) && now.isBefore(p.notAfter()), "command.window");
        JsonNode head = bind(registry, p, clock);
        CommandLink.Release release = CommandLink.Release.of(registry, head);
        CommandLink.Link link = link(release, p);
        // The precondition is the member the link's read binding names, read from the release, not from the proposal.
        JsonNode mappings = release.json(link.mappingSetPath(), "command.precondition", "mapping-set");
        JsonNode mapping = null;
        for (JsonNode m : mappings.path("mappings")) if (text(m, "mappingId").equals(link.binding().mappingId())) mapping = m;
        require(mapping != null && text(mapping.path("valueRef"), "kind").equals("source") && mapping.path("temporalPolicy").path("maxAgeMs").canConvertToLong()
            && mapping.path("temporalPolicy").path("maxAgeMs").asLong() > 0, "command.precondition");
        JsonNode ref = mapping.path("valueRef").path("sourceRef");
        String node = null;
        for (String path : new TreeSet<>(release.files().keySet())) {
            if (!path.startsWith("payload/sources/")) continue;
            JsonNode src = release.json(path, "command.precondition", "source");
            if (!text(src, "kind").equals("source-definition") || !text(src, "id").equals(text(ref, "id")) || !text(src, "version").equals(text(ref, "version"))) continue;
            JsonNode a = src.path("access");
            require(node == null && text(a, "kind").equals("opcua-node") && text(a, "identifierType").equals("string") && nonEmpty(a, "namespaceUri") && nonEmpty(a, "identifier"), "command.precondition");
            node = "nsu=" + text(a, "namespaceUri") + ";s=" + text(a, "identifier");
        }
        require(node != null, "command.precondition");
        return new Admitted(p, head, link, node, mapping.path("temporalPolicy").path("maxAgeMs").asLong());
    }

    /** The proposer's signature verifies and another signature verifies under a registered principal other than
     *  approvedBy: the co-signer is the wrong person, not a broken signature. */
    private static boolean signedByOther(Path registry, JsonNode envelope) {
        Proposal p = parse(Base64.getDecoder().decode(text(envelope, "payload")));
        AuthorizedKeys keys = AuthorizedKeys.load(registry);
        try {Dsse.verify(envelope, Dsse.IN_TOTO, keys, List.of(p.proposedBy()));} catch (IdentityException e) {return false;}
        byte[] pae = Dsse.pae(Dsse.IN_TOTO, p.payload());
        for (JsonNode s : envelope.path("signatures")) {
            String by = text(s, "keyid");
            if (!by.isEmpty() && !by.equals(p.proposedBy()) && !by.equals(p.approvedBy()) && keys.verifying(by, pae, text(s, "sig")).isPresent()) return true;
        }
        return false;
    }

    /** DSSE verification under the registered keys, then the statement's shape. A wrong key, a changed byte or a
     *  re-serialized payload is command.signature; two principals on one key is identity.four-eyes.same-key. */
    private static Proposal signed(Path registry, JsonNode envelope, boolean approved) {
        byte[] payload;
        try {payload = Base64.getDecoder().decode(text(envelope, "payload"));} catch (IllegalArgumentException e) {throw new IllegalArgumentException("command.malformed");}
        Proposal p = parse(payload);
        try {
            Dsse.verify(envelope, Dsse.IN_TOTO, AuthorizedKeys.load(registry), approved ? List.of(p.proposedBy(), p.approvedBy()) : List.of(p.proposedBy()));
        } catch (IdentityException e) {
            throw new IllegalArgumentException(e.rule().equals("identity.four-eyes.same-key") ? e.rule() : "command.signature");
        }
        return p;
    }

    /** The head this registry serves now must be the head and release the proposal pins, and the evidence must be a usable
     *  Vor answer read from that same release of that stream. */
    private static JsonNode bind(Path registry, Proposal p, Clock clock) throws Exception {
        JsonNode head = new MappingRegistry(registry, clock, () -> {}).verifyHead(p.streamId()).path("head");
        byte[] headBytes = Files.readAllBytes(registry.resolve("mappings/heads/" + p.streamId() + ".json"));
        String release = "releases/" + text(head, "id") + "/" + text(head, "version") + "/release.json";
        require(JSON.readTree(headBytes).equals(head) && sha(headBytes).equals(p.subject(0))
            && text(p.statement().path("subject").get(1), "name").equals(release) && text(head, "sha256").equals(p.subject(1))
            && sha(registry.resolve("mappings/" + release)).equals(p.subject(1)), "command.head.mismatch");
        JsonNode answer;
        try {answer = JSON.readTree(p.evidence());} catch (Exception e) {throw new IllegalArgumentException("command.malformed");}
        require(answer != null && answer.isObject() && answer.path("verdict").isObject(), "command.malformed");
        require(answer.path("verdict").path("usable").isBoolean() && answer.path("verdict").path("usable").asBoolean() && answer.path("answer").isObject(), "command.evidence.unusable");
        JsonNode pin = answer.path("answer").path("pin");
        require(text(pin, "stream_id").equals(p.streamId()) && text(pin, "release_id").equals(text(head, "id"))
            && text(pin, "version").equals(text(head, "version")) && text(pin, "release_sha256").equals(text(head, "sha256")), "command.head.mismatch");
        return head;
    }

    /** The command binding for the proposal in the release the head names, and the proposal and evidence matching it. */
    private static CommandLink.Link link(Path registry, Proposal p, JsonNode head) throws Exception {
        return link(CommandLink.Release.of(registry, head), p);
    }

    private static CommandLink.Link link(CommandLink.Release release, Proposal p) throws Exception {
        CommandLink.Link link = CommandLink.resolve(release, p);
        CommandLink.match(release, link, p, JSON.readTree(p.evidence()).path("answer"));
        // A link that names no server authorizes no call: 2.25.0 links are read, never acted on.
        link.requireEndpoint();
        return link;
    }

    private static ObjectNode summary(String kind, Proposal p, JsonNode head) {
        ObjectNode r = object().put("kind", kind).put("accepted", true).put("cmdId", p.cmdId()).put("streamId", p.streamId());
        r.putObject("target").put("group", p.target().group()).put("edge", p.target().edge()).put("device", p.target().device());
        r.put("methodNodeId", p.methodNodeId()).put("input", p.input()).put("value", p.value())
            .put("notBefore", p.notBefore().toString()).put("notAfter", p.notAfter().toString())
            .put("proposedBy", p.proposedBy()).put("approvedBy", p.approvedBy());
        r.set("head", head.deepCopy());
        return r.put("execution", "excluded");
    }

    private static boolean nonEmpty(JsonNode n, String k) {return n.path(k).isTextual() && !n.path(k).asText().isEmpty();}
    private static Instant instant(JsonNode n, String k) {
        try {return Instant.parse(text(n, k));} catch (RuntimeException e) {throw new IllegalArgumentException("command.malformed");}
    }
}
