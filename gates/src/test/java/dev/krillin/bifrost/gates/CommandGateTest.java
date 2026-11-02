package dev.krillin.bifrost.gates;

import com.fasterxml.jackson.databind.node.*;
import dev.krillin.bifrost.core.command.CommandProposal;
import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
import static dev.krillin.bifrost.gates.MappingGateTest.cli;
import static org.junit.jupiter.api.Assertions.*;

/** gates command verify|approve over the Vor read release, through the dispatcher. */
class CommandGateTest {
    static final String METHOD="nsu=urn:bifrost:opcua:sim;s=Line1/Mixer1.SetTemperature";

    @Test void verifyApproveVerifyThroughTheCli(@TempDir Path dir) throws Exception {
        Path fixture=Path.of("../core/src/test/resources/mapping-fixtures/vor-read");assertTrue(Files.isDirectory(fixture),"core vor-read fixture");
        Path bundle=dir.resolve("bundle");try(var walk=Files.walk(fixture)){for(Path p:walk.toList()){Path t=bundle.resolve(fixture.relativize(p).toString());if(Files.isDirectory(p))Files.createDirectories(t);else Files.copy(p,t);}}
        Path reg=dir.resolve("registry"),keys=dir.resolve("keys");Files.createDirectories(reg.resolve("identity"));
        StringBuilder pub=new StringBuilder();
        for(String who:new String[]{"proposer","approver","agent","operator"}){
            PrintStream old=System.out;ByteArrayOutputStream sink=new ByteArrayOutputStream();
            try{System.setOut(new PrintStream(sink));assertEquals(0,IdentityGate.run(new String[]{"keygen",who,"--out",keys.toString()}));}finally{System.setOut(old);}
            pub.append(sink.toString(StandardCharsets.UTF_8).strip()).append('\n');
        }
        Files.writeString(reg.resolve("identity/authorized-keys.jsonl"),pub.toString());
        Files.writeString(reg.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":["
            +"{\"id\":\"p\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"line1\"},"
            +"{\"id\":\"a\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"line1\"},"
            +"{\"id\":\"propose\",\"principal\":\"agent\",\"action\":\"propose_command\",\"target\":\"command\",\"kind\":\"method\",\"ref\":\"line1\"},"
            +"{\"id\":\"co-sign\",\"principal\":\"operator\",\"action\":\"approve_command\",\"target\":\"command\",\"kind\":\"method\",\"ref\":\"line1\"}]}");
        String pk=keys.resolve("proposer.key").toString(),ak=keys.resolve("approver.key").toString(),r=reg.toString();
        cli(0,"mapping","approve",r,bundle.toString(),"approval-1","--by","proposer","--by-key",pk,"--approved-by","approver","--approved-by-key",ak);
        cli(0,"mapping","publish",r,bundle.toString(),"vor-read","1.0.0","--approval","approval-1","--by","proposer","--by-key",pk,"--approved-by","approver","--approved-by-key",ak);
        var head=read(reg.resolve("mappings/heads/line1.json"));
        Path policy=dir.resolve("command-policy.json");
        Files.writeString(policy,"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"set-temp\",\"principal\":\"agent\",\"target\":{\"group\":\"Bifrost:Line1\",\"edge\":\"heimdall-edge\",\"device\":\"Line1/Mixer1\"},\"command\":\""+METHOD+"\",\"constraint\":{\"type\":\"Double\",\"min\":0.0,\"max\":100.0}}]}");

        ObjectNode answer=object();
        answer.putObject("answer").putObject("pin").put("stream_id","line1").put("release_id","vor-read").put("version","1.0.0").put("release_sha256",text(head,"sha256"));
        answer.putObject("verdict").put("usable",true).put("status","usable");
        byte[] evidence=JSON.writeValueAsBytes(answer);
        Instant now=Instant.now().truncatedTo(ChronoUnit.SECONDS);
        ObjectNode s=object();s.put("_type",CommandProposal.STATEMENT);
        ArrayNode sub=s.putArray("subject");
        sub.add(object().put("name","heads/line1.json").set("digest",object().put("sha256",sha(reg.resolve("mappings/heads/line1.json")))));
        sub.add(object().put("name","releases/vor-read/1.0.0/release.json").set("digest",object().put("sha256",text(head,"sha256"))));
        sub.add(object().put("name","evidence").set("digest",object().put("sha256",sha(evidence))));
        s.put("predicateType",CommandProposal.PREDICATE);
        ObjectNode p=s.putObject("predicate");
        p.put("cmdId",UUID.randomUUID().toString()).put("streamId","line1");
        p.putObject("target").put("group","Bifrost:Line1").put("edge","heimdall-edge").put("device","Line1/Mixer1");
        ObjectNode m=p.putObject("method");m.put("objectNodeId","nsu=urn:bifrost:opcua:sim;s=Line1/Mixer1").put("methodNodeId",METHOD);
        m.putArray("inputs").addObject().put("name","targetTemperature").put("type","Double").put("value",42.0);
        p.putObject("validity").put("notBefore",now.toString()).put("notAfter",now.plus(Duration.ofMinutes(10)).toString());
        p.put("proposedBy","agent").put("approvedBy","operator");
        p.putObject("evidence").put("mediaType","application/json").put("base64",Base64.getEncoder().encodeToString(evidence));
        byte[] payload=JSON.writeValueAsBytes(s);
        var agent=Ed25519Keys.privateKey(Files.readString(keys.resolve("agent.key")).strip());
        Path proposal=dir.resolve("proposal.dsse.json");
        Files.write(proposal,JSON.writeValueAsBytes(Dsse.envelope(Dsse.IN_TOTO,payload,List.of(new Dsse.Signature("agent",Ed25519Keys.sign(Dsse.pae(Dsse.IN_TOTO,payload),agent))))));

        assertEquals("command-proposal-verification",text(cli(0,"command","verify",r,proposal.toString()),"kind"));
        assertEquals("command.signature",text(cli(1,"command","verify",r,proposal.toString(),"--approved"),"error"));
        String ok=keys.resolve("operator.key").toString(),out=dir.resolve("approved.dsse.json").toString();
        assertEquals("command.approver.mismatch",text(cli(1,"command","approve",r,proposal.toString(),"--approved-by","approver","--approved-by-key",ak,"--policy",policy.toString(),"--out",out),"error"));
        assertFalse(Files.exists(Path.of(out)),"a refusal writes nothing");
        var approved=cli(0,"command","approve",r,proposal.toString(),"--approved-by","operator","--approved-by-key",ok,"--policy",policy.toString(),"--out",out);
        assertEquals("command-approval",text(approved,"kind"));assertEquals("set-temp",text(approved,"policyRule"));
        assertEquals("command-approved-verification",text(cli(0,"command","verify",r,out,"--approved"),"kind"));
        assertEquals("command.out-exists",text(cli(1,"command","approve",r,proposal.toString(),"--approved-by","operator","--approved-by-key",ok,"--policy",policy.toString(),"--out",out),"error"));
        assertEquals(2,GatesCli.run(new String[]{"command","approve",r}));
    }
}
