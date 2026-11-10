package yggdrasil.bifrost.gates;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import yggdrasil.bifrost.core.command.CommandProposal;
import yggdrasil.bifrost.core.identity.Dsse;
import yggdrasil.bifrost.core.identity.Ed25519Keys;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import static yggdrasil.bifrost.core.mapping.MappingJson.*;

/** Gate support for scripts/run-command-method-gate.sh, deliberately not a `gates` subcommand. The agent's proposal is
 *  vor-propose's job (in the vor repository); the Method gate needs signed proposals without depending on another
 *  repository, so this writes one the way the statement contract defines it, with an evidence answer that pins the
 *  registry's current head, names the mixer's mapping and carries the binding its released read binding names.
 *  The refusal legs bend one thing each: --mixer picks the target and Method, --evidence-mixer whose evidence rides
 *  along, --device the target device, --binding-sha256 the evidence's binding.source digest, --predicate the type.
 *  <pre>
 *  propose &lt;registry&gt; &lt;out&gt; --by &lt;id&gt; --by-key &lt;path&gt; --approved-by &lt;id&gt; --value &lt;v&gt; --not-before &lt;iso&gt; --not-after &lt;iso&gt;
 *          [--edge &lt;id&gt;] [--mixer 1|2] [--evidence-mixer 1|2] [--device &lt;id&gt;] [--binding-sha256 &lt;hex&gt;] [--predicate &lt;uri&gt;]
 *  rebase  &lt;bundle&gt; &lt;registry&gt; &lt;out&gt; &lt;submission-id&gt;   (a copy of the bundle whose base is the stream's current head)
 *  cosign  &lt;envelope&gt; &lt;out&gt; --by &lt;id&gt; --by-key &lt;path&gt;   (adds a signature over the same bytes, checking nothing:
 *          an approval `gates command approve` refused, so the edge's own checks are the only ones left)
 *  </pre> */
public final class ProposalFixture {
    static final String GROUP = "Bifrost:Line1";
    private ProposalFixture() {}

    public static void main(String[] a) throws Exception {
        switch (a[0]) {
            case "propose" -> propose(Path.of(a[1]), Path.of(a[2]), opt(a, "--by"), Path.of(opt(a, "--by-key")), opt(a, "--approved-by"),
                Double.parseDouble(opt(a, "--value")), opt(a, "--not-before"), opt(a, "--not-after"), opt(a, "--edge"),
                Integer.parseInt(Objects.requireNonNullElse(opt(a, "--mixer"), "1")),
                Integer.parseInt(Objects.requireNonNullElse(opt(a, "--evidence-mixer"), Objects.requireNonNullElse(opt(a, "--mixer"), "1"))),
                opt(a, "--device"), opt(a, "--binding-sha256"), Objects.requireNonNullElse(opt(a, "--predicate"), CommandProposal.PREDICATE));
            case "rebase" -> rebase(Path.of(a[1]), Path.of(a[2]), Path.of(a[3]), a[4]);
            case "cosign" -> cosign(Path.of(a[1]), Path.of(a[2]), opt(a, "--by"), Path.of(opt(a, "--by-key")));
            default -> throw new IllegalArgumentException("usage: propose|rebase|cosign");
        }
    }

    static void propose(Path registry, Path out, String by, Path byKey, String approvedBy, double value, String notBefore,
                        String notAfter, String edge, int mixer, int evidenceMixer, String device, String bindingSha256,
                        String predicate) throws Exception {
        String stream = "line1";
        byte[] headBytes = Files.readAllBytes(registry.resolve("mappings/heads/" + stream + ".json"));
        JsonNode head = JSON.readTree(headBytes);
        String file = "mappings/releases/" + text(head, "id") + "/" + text(head, "version") + "/payload/data/"
            + (evidenceMixer == 1 ? "vor-read-binding.json" : "vor-read-binding-mixer2.json");
        byte[] bindingBytes = Files.readAllBytes(registry.resolve(file));
        JsonNode released = JSON.readTree(bindingBytes);
        ObjectNode answer = object();
        ObjectNode ans = answer.putObject("answer");
        ans.putObject("pin").put("stream_id", stream).put("release_id", text(head, "id"))
            .put("version", text(head, "version")).put("release_sha256", text(head, "sha256"))
            .put("file", "payload/mappings/" + (evidenceMixer - 1) + ".json").put("field_id", evidenceMixer == 1 ? "temp" : "temp-mixer2");
        ObjectNode binding = ans.putObject("binding");
        for (String f : List.of("group", "edge", "device", "metric")) binding.put(f, text(released, f));
        binding.set("governedDefinitionRef", released.path("governedDefinitionRef").deepCopy());
        binding.putObject("source").put("file", file).put("sha256", bindingSha256 == null ? sha(bindingBytes) : bindingSha256);
        answer.putObject("verdict").put("usable", true).put("status", "usable");
        byte[] evidence = JSON.writeValueAsBytes(answer);

        ObjectNode s = object().put("_type", CommandProposal.STATEMENT);
        ArrayNode sub = s.putArray("subject");
        sub.add(object().put("name", "heads/" + stream + ".json").set("digest", object().put("sha256", sha(headBytes))));
        sub.add(object().put("name", "releases/" + text(head, "id") + "/" + text(head, "version") + "/release.json")
            .set("digest", object().put("sha256", text(head, "sha256"))));
        sub.add(object().put("name", "evidence").set("digest", object().put("sha256", sha(evidence))));
        s.put("predicateType", predicate);
        ObjectNode p = s.putObject("predicate");
        p.put("cmdId", UUID.randomUUID().toString()).put("streamId", stream);
        p.putObject("target").put("group", GROUP).put("edge", edge == null ? "recipe-edge-cmd" : edge).put("device",
            device == null ? "synthetic-site:line1:mixer" + mixer : device);
        String object = "nsu=urn:bifrost:opcua:sim;s=Line1/Mixer" + mixer;
        ObjectNode m = p.putObject("method");
        m.put("objectNodeId", object).put("methodNodeId", object + ".SetTemperature");
        m.putArray("inputs").addObject().put("name", "targetTemperature").put("type", "Double").put("value", value);
        p.putObject("validity").put("notBefore", notBefore).put("notAfter", notAfter);
        p.put("proposedBy", by).put("approvedBy", approvedBy);
        p.putObject("evidence").put("mediaType", "application/json").put("base64", Base64.getEncoder().encodeToString(evidence));

        byte[] payload = JSON.writeValueAsBytes(s);
        var key = Ed25519Keys.privateKey(Files.readString(byKey, StandardCharsets.UTF_8).trim());
        ObjectNode env = Dsse.envelope(Dsse.IN_TOTO, payload, List.of(new Dsse.Signature(by, Ed25519Keys.sign(Dsse.pae(Dsse.IN_TOTO, payload), key))));
        Files.write(out, JSON.writeValueAsBytes(env), StandardOpenOption.CREATE_NEW);
        System.out.println(text(p, "cmdId"));
    }

    static void cosign(Path in, Path out, String by, Path byKey) throws Exception {
        JsonNode env = read(in);
        byte[] payload = Base64.getDecoder().decode(text(env, "payload"));
        List<Dsse.Signature> sigs = new ArrayList<>();
        for (JsonNode s : env.path("signatures")) sigs.add(new Dsse.Signature(text(s, "keyid"), text(s, "sig")));
        var key = Ed25519Keys.privateKey(Files.readString(byKey, StandardCharsets.UTF_8).trim());
        sigs.add(new Dsse.Signature(by, Ed25519Keys.sign(Dsse.pae(Dsse.IN_TOTO, payload), key)));
        Files.write(out, JSON.writeValueAsBytes(Dsse.envelope(Dsse.IN_TOTO, payload, sigs)), StandardOpenOption.CREATE_NEW);
    }

    static void rebase(Path bundle, Path registry, Path out, String submissionId) throws Exception {
        try (var walk = Files.walk(bundle)) {
            for (Path f : walk.toList()) {
                Path q = out.resolve(bundle.relativize(f).toString());
                if (Files.isDirectory(f)) Files.createDirectories(q); else Files.copy(f, q);
            }
        }
        JsonNode head = read(registry.resolve("mappings/heads/line1.json"));
        ObjectNode proposal = (ObjectNode) read(out.resolve("proposal.json"));
        proposal.set("baseRelease", head);
        Files.write(out.resolve("proposal.json"), JSON.writeValueAsBytes(proposal));
        ObjectNode submission = (ObjectNode) read(out.resolve("submission.json"));
        submission.put("id", submissionId).set("baseRelease", head);
        submission.put("proposalSha256", sha(out.resolve("proposal.json")));
        Files.write(out.resolve("submission.json"), JSON.writeValueAsBytes(submission));
    }

    private static String opt(String[] a, String flag) {
        for (int i = 0; i < a.length - 1; i++) if (a[i].equals(flag)) return a[i + 1];
        return null;
    }
}
