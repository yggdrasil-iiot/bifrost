package dev.krillin.bifrost.core.command;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import dev.krillin.bifrost.core.identity.*;
import dev.krillin.bifrost.core.mapping.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

/** A command proposal over the Vor read release: the agent signs it, the approver re-checks it against the registry and
 *  co-signs the same bytes, and every refusal carries its reason code. */
class CommandProposalTest {
    static final String OBJECT="nsu=urn:bifrost:opcua:sim;s=Line1/Mixer1",METHOD="nsu=urn:bifrost:opcua:sim;s=Line1/Mixer1.SetTemperature";
    static final String CMD="0f0e8f43-6a43-4d0e-9a3a-2b6f1f5f0c11";
    static final class MovableClock extends Clock {
        Instant now=Instant.parse("2026-11-01T00:00:00Z");
        @Override public ZoneId getZone(){return ZoneOffset.UTC;}
        @Override public Clock withZone(ZoneId zone){return this;}
        @Override public Instant instant(){return now;}
    }
    @TempDir Path tmp;
    Path registry,policy,operatorKey,otherKey;
    PrivateKey agent;
    String agentPub;
    MovableClock clock=new MovableClock();
    JsonNode head;

    @BeforeEach void setup() throws Exception {
        Path bundle=tmp.resolve("bundle");copy(Path.of(getClass().getResource("/mapping-fixtures/vor-read").toURI()),bundle);
        registry=tmp.resolve("registry");Files.createDirectories(registry.resolve("identity"));
        Map<String,KeyPair> k=new LinkedHashMap<>();
        for(String p:List.of("proposer","approver","agent","operator","other"))k.put(p,Ed25519Keys.generate());
        agent=k.get("agent").getPrivate();agentPub=Ed25519Keys.publicKeyB64(k.get("agent").getPublic());
        operatorKey=key("operator",k);otherKey=key("other",k);
        StringBuilder keys=new StringBuilder();
        for(var e:k.entrySet())keys.append(JSON.writeValueAsString(new AuthorizedKey(e.getKey(),Ed25519Keys.publicKeyB64(e.getValue().getPublic())))).append('\n');
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),keys);
        grants(true,true);
        var service=new MappingRegistry(registry,clock,()->{});
        service.approve(bundle,"approval-1","proposer",key("proposer",k),"approver",key("approver",k));
        service.publish(bundle,"vor-read","1.0.0","approval-1",new MappingRegistry.HeadSigners("proposer",key("proposer",k),"approver",key("approver",k),Duration.ofDays(90)));
        head=read(registry.resolve("mappings/heads/line1.json"));
        policy=tmp.resolve("command-policy.json");
        Files.writeString(policy,"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"set-temp\",\"principal\":\"agent\",\"target\":{\"group\":\"Bifrost:Line1\",\"edge\":\"heimdall-edge\",\"device\":\"Line1/Mixer1\"},\"command\":\""+METHOD+"\",\"constraint\":{\"type\":\"Double\",\"min\":0.0,\"max\":100.0}}]}");
    }
    static void copy(Path source,Path dest) throws Exception {
        try(var walk=Files.walk(source)){for(Path p:walk.toList()){Path q=dest.resolve(source.relativize(p));if(Files.isDirectory(p))Files.createDirectories(q);else Files.copy(p,q);}}
    }
    Path key(String p,Map<String,KeyPair> k) throws Exception {
        Path f=tmp.resolve(p+".key");if(!Files.exists(f))Files.writeString(f,Ed25519Keys.privateKeyB64(k.get(p).getPrivate()));return f;
    }
    void grants(boolean propose,boolean approve) throws Exception {
        List<String> rules=new ArrayList<>(List.of(
            "{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"line1\"}",
            "{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"line1\"}",
            // Activation roles on the same principals must not stand in for command grants.
            "{\"id\":\"agent-activates\",\"principal\":\"agent\",\"action\":\"activate\",\"target\":\"command\",\"kind\":\"method\",\"ref\":\"line1\"}",
            "{\"id\":\"operator-approves\",\"principal\":\"operator\",\"action\":\"approve\",\"target\":\"command\",\"kind\":\"method\",\"ref\":\"line1\"}"));
        if(propose)rules.add("{\"id\":\"agent-proposes\",\"principal\":\"agent\",\"action\":\"propose_command\",\"target\":\"command\",\"kind\":\"method\",\"ref\":\"line1\"}");
        if(approve)rules.add("{\"id\":\"operator-co-signs\",\"principal\":\"operator\",\"action\":\"approve_command\",\"target\":\"command\",\"kind\":\"method\",\"ref\":\"line1\"}");
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":["+String.join(",",rules)+"]}");
    }

    /** What Vor's read_governed returns for Line1/Mixer1.Temp on this release; only the fields approval reads matter. */
    ObjectNode answer(){
        ObjectNode a=object();
        a.putObject("answer").putObject("pin").put("stream_id","line1").put("release_id",text(head,"id")).put("version",text(head,"version")).put("release_sha256",text(head,"sha256"));
        a.putObject("verdict").put("usable",true).put("status","usable");
        return a;
    }
    ObjectNode statement(byte[] evidence) throws Exception {
        ObjectNode s=object();s.put("_type",CommandProposal.STATEMENT);
        ArrayNode sub=s.putArray("subject");
        sub.add(object().put("name","heads/line1.json").set("digest",object().put("sha256",sha(registry.resolve("mappings/heads/line1.json")))));
        sub.add(object().put("name","releases/vor-read/1.0.0/release.json").set("digest",object().put("sha256",text(head,"sha256"))));
        sub.add(object().put("name","evidence").set("digest",object().put("sha256",sha(evidence))));
        s.put("predicateType",CommandProposal.PREDICATE);
        ObjectNode p=s.putObject("predicate");
        p.put("cmdId",CMD).put("streamId","line1");
        p.putObject("target").put("group","Bifrost:Line1").put("edge","heimdall-edge").put("device","Line1/Mixer1");
        ObjectNode m=p.putObject("method");m.put("objectNodeId",OBJECT).put("methodNodeId",METHOD);
        m.putArray("inputs").addObject().put("name","targetTemperature").put("type","Double").put("value",42.0);
        p.putObject("validity").put("notBefore","2026-11-01T00:00:00Z").put("notAfter","2026-11-01T00:15:00Z");
        p.put("proposedBy","agent").put("approvedBy","operator");
        p.putObject("evidence").put("mediaType","application/json").put("base64",Base64.getEncoder().encodeToString(evidence));
        return s;
    }
    JsonNode sign(byte[] payload,PrivateKey key){return Dsse.envelope(Dsse.IN_TOTO,payload,List.of(new Dsse.Signature("agent",Ed25519Keys.sign(Dsse.pae(Dsse.IN_TOTO,payload),key))));}
    JsonNode proposal(Consumer<ObjectNode> edit) throws Exception {return proposal(JSON.writeValueAsBytes(answer()),edit);}
    JsonNode proposal(byte[] evidence,Consumer<ObjectNode> edit) throws Exception {
        ObjectNode s=statement(evidence);edit.accept(s);return sign(JSON.writeValueAsBytes(s),agent);
    }
    JsonNode proposal() throws Exception {return proposal(s->{});}
    static ObjectNode predicate(ObjectNode s){return (ObjectNode)s.get("predicate");}
    CommandProposal.Approval approve(JsonNode env,String approver,Path key) throws Exception {return CommandProposal.approve(registry,env,approver,key,policy,clock);}
    CommandProposal.Approval approve(JsonNode env) throws Exception {return approve(env,"operator",operatorKey);}
    static String refusal(org.junit.jupiter.api.function.Executable e){return assertThrows(IllegalArgumentException.class,e).getMessage();}
    String approveRefusal(JsonNode env){return refusal(()->approve(env));}

    @Test void approvalCoSignsTheSameBytes() throws Exception {
        JsonNode env=proposal();
        var a=approve(env);
        assertEquals(text(env,"payload"),text(a.envelope(),"payload"),"payload is never re-serialized");
        assertEquals(2,a.envelope().path("signatures").size());
        assertEquals(env.path("signatures").get(0),a.envelope().path("signatures").get(0),"the agent's signature is kept as it was");
        assertEquals("operator",text(a.envelope().path("signatures").get(1),"keyid"));
        assertEquals("set-temp",text(a.report(),"policyRule"));
        assertEquals("agent-proposes",text(a.report(),"proposeGrant"));assertEquals("operator-co-signs",text(a.report(),"approveGrant"));
        JsonNode v=CommandProposal.verify(registry,a.envelope(),true,clock);
        assertEquals("command-approved-verification",text(v,"kind"));assertEquals(CMD,text(v,"cmdId"));assertEquals(42.0,v.path("value").asDouble());
        assertEquals(head,v.path("head"));
    }

    @Test void proposalVerifiesWithOneSignature() throws Exception {
        assertEquals("command-proposal-verification",text(CommandProposal.verify(registry,proposal(),false,clock),"kind"));
        assertEquals("command.signature",refusal(()->CommandProposal.verify(registry,proposal(),true,clock)),"a proposal is not an approved envelope");
        JsonNode approved=approve(proposal()).envelope();
        assertEquals("command.signature",refusal(()->CommandProposal.verify(registry,approved,false,clock)));
        assertEquals("command.signature",approveRefusal(approved),"an approved envelope is not approved again");
    }

    @Test void approverMustBeTheNamedOne() throws Exception {
        assertEquals("command.approver.mismatch",refusal(()->approve(proposal(),"other",otherKey)));
    }

    /** "other" is a separately registered principal, but on the agent's key: two signatures on one key are one person. */
    @Test void sameKeyIsOnePerson() throws Exception {
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),JSON.writeValueAsString(new AuthorizedKey("other",agentPub))+"\n",StandardOpenOption.APPEND);
        Path agentKey=tmp.resolve("agent-as-other.key");Files.writeString(agentKey,Ed25519Keys.privateKeyB64(agent));
        Files.writeString(registry.resolve("identity/activation-policy.json"),Files.readString(registry.resolve("identity/activation-policy.json")).replace("\"principal\":\"operator\",\"action\":\"approve_command\"","\"principal\":\"other\",\"action\":\"approve_command\""));
        JsonNode env=proposal(s->predicate(s).put("approvedBy","other"));
        assertEquals("identity.four-eyes.same-key",refusal(()->approve(env,"other",agentKey)));
        assertEquals("identity.four-eyes.same-key",refusal(()->CommandProposal.parse(Base64.getDecoder().decode(text(proposal(s->predicate(s).put("approvedBy","agent")),"payload")))),"proposer and approver must differ");
    }

    @Test void windowAtMostFifteenMinutes() throws Exception {
        JsonNode exact=proposal();approve(exact);
        JsonNode over=proposal(s->((ObjectNode)predicate(s).get("validity")).put("notAfter","2026-11-01T00:15:01Z"));
        assertEquals("command.window",approveRefusal(over));
        assertEquals("command.window",refusal(()->CommandProposal.verify(registry,over,false,clock)));
        JsonNode backwards=proposal(s->((ObjectNode)predicate(s).get("validity")).put("notBefore","2026-11-01T00:15:00Z"));
        assertEquals("command.window",approveRefusal(backwards));
    }

    @Test void expiredProposalIsNotApproved() throws Exception {
        JsonNode env=proposal();clock.now=Instant.parse("2026-11-01T00:15:00Z");
        assertEquals("command.window",approveRefusal(env));
    }

    @Test void changedByteFailsTheSignature() throws Exception {
        ObjectNode env=(ObjectNode)proposal();byte[] payload=Base64.getDecoder().decode(text(env,"payload"));
        String body=new String(payload,StandardCharsets.UTF_8);
        int at=body.indexOf("42.0");assertTrue(at>0);
        payload[at]='9';
        env.put("payload",Base64.getEncoder().encodeToString(payload));
        assertEquals("command.signature",approveRefusal(env));
        assertEquals("command.signature",refusal(()->CommandProposal.verify(registry,env,false,clock)));
    }

    @Test void reserializedPayloadFailsTheSignature() throws Exception {
        ObjectNode env=(ObjectNode)proposal();
        byte[] same=JSON.writerWithDefaultPrettyPrinter().writeValueAsBytes(JSON.readTree(Base64.getDecoder().decode(text(env,"payload"))));
        assertEquals(JSON.readTree(same),JSON.readTree(Base64.getDecoder().decode(text(env,"payload"))),"the same statement, other bytes");
        env.put("payload",Base64.getEncoder().encodeToString(same));
        assertEquals("command.signature",approveRefusal(env));
    }

    @Test void onlyTheProposerCanSign() throws Exception {
        PrivateKey operator=Ed25519Keys.privateKey(Files.readString(operatorKey));
        JsonNode forged=sign(JSON.writeValueAsBytes(statement(JSON.writeValueAsBytes(answer()))),operator);
        assertEquals("command.signature",approveRefusal(forged));
        assertEquals("command.signature",refusal(()->CommandProposal.verify(registry,forged,false,clock)));
    }

    @Test void subjectsMustBeTheCurrentHead() throws Exception {
        assertEquals("command.head.mismatch",approveRefusal(proposal(s->((ObjectNode)s.get("subject").get(0).get("digest")).put("sha256","0".repeat(64)))));
        assertEquals("command.head.mismatch",approveRefusal(proposal(s->((ObjectNode)s.get("subject").get(1).get("digest")).put("sha256","0".repeat(64)))));
        assertEquals("command.head.mismatch",approveRefusal(proposal(s->((ObjectNode)s.get("subject").get(1)).put("name","releases/vor-read/0.9.0/release.json"))));
    }

    @Test void evidenceMustPinTheSameRelease() throws Exception {
        ObjectNode a=answer();((ObjectNode)a.get("answer").get("pin")).put("release_sha256","0".repeat(64));
        assertEquals("command.head.mismatch",approveRefusal(proposal(JSON.writeValueAsBytes(a),s->{})));
        ObjectNode b=answer();((ObjectNode)b.get("answer").get("pin")).put("stream_id","line2");
        assertEquals("command.head.mismatch",approveRefusal(proposal(JSON.writeValueAsBytes(b),s->{})));
    }

    @Test void unusableEvidenceIsRefused() throws Exception {
        ObjectNode refused=object();refused.putNull("answer");refused.putObject("verdict").put("usable",false).put("reason","bad-quality");
        assertEquals("command.evidence.unusable",approveRefusal(proposal(JSON.writeValueAsBytes(refused),s->{})));
        ObjectNode flagged=answer();((ObjectNode)flagged.get("verdict")).put("usable",false);
        assertEquals("command.evidence.unusable",approveRefusal(proposal(JSON.writeValueAsBytes(flagged),s->{})),"the verdict decides, not the presence of an answer");
    }

    @Test void evidenceMustMatchItsDigest() throws Exception {
        byte[] other=JSON.writeValueAsBytes(answer().put("extra",1));
        assertEquals("command.evidence.digest",approveRefusal(proposal(s->((ObjectNode)predicate(s).get("evidence")).put("base64",Base64.getEncoder().encodeToString(other)))));
    }

    @Test void boundsComeFromTheCommandPolicy() throws Exception {
        approve(proposal(s->((ObjectNode)predicate(s).get("method").get("inputs").get(0)).put("value",100.0)));
        assertEquals("command.policy.denied",approveRefusal(proposal(s->((ObjectNode)predicate(s).get("method").get("inputs").get(0)).put("value",150.0))));
        Files.writeString(policy,Files.readString(policy).replace("\"principal\":\"agent\"","\"principal\":\"other\""));
        assertEquals("command.policy.denied",approveRefusal(proposal()),"the policy names the principal that may propose this call");
    }

    @Test void grantsAreCommandGrants() throws Exception {
        grants(true,false);
        assertEquals("command.grant",approveRefusal(proposal()),"approve on the same resource is not approve_command");
        grants(false,true);
        assertEquals("command.grant",approveRefusal(proposal()),"activate is not propose_command");
    }

    @Test void malformedStatementsAreRefused() throws Exception {
        assertEquals("command.malformed",approveRefusal(proposal(s->predicate(s).put("cmdId","not-a-uuid"))));
        assertEquals("command.malformed",approveRefusal(proposal(s->predicate(s).put("evidenceSha256","0".repeat(64)))));
        assertEquals("command.malformed",approveRefusal(proposal(s->((ArrayNode)predicate(s).get("method").get("inputs")).addObject().put("name","x").put("type","Double").put("value",1.0))));
        assertEquals("command.malformed",approveRefusal(proposal(s->((ObjectNode)predicate(s).get("method").get("inputs").get(0)).put("value","42"))));
        assertEquals("command.malformed",approveRefusal(proposal(s->((ObjectNode)predicate(s).get("method")).put("methodNodeId","ns=2;s=Line1/Mixer1.SetTemperature"))));
        assertEquals("command.malformed",approveRefusal(proposal(s->((ObjectNode)predicate(s).get("validity")).put("notAfter","2026-11-01T00:15:00.5Z"))));
    }
}
