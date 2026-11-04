package dev.krillin.bifrost.gates;

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
        Files.writeString(policy,"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"set-temp\",\"principal\":\"agent\",\"target\":{\"group\":\"Bifrost:Line1\",\"edge\":\"recipe-edge-cmd\",\"device\":\"synthetic-site:line1:mixer1\"},\"command\":\""+METHOD+"\",\"constraint\":{\"type\":\"Double\",\"min\":0.0,\"max\":100.0}}]}");

        Instant now=Instant.now().truncatedTo(ChronoUnit.SECONDS);
        String nb=now.toString(),na=now.plus(Duration.ofMinutes(10)).toString(),agent=keys.resolve("agent.key").toString();
        Path proposal=dir.resolve("proposal.dsse.json"),cross=dir.resolve("cross.dsse.json");
        ProposalFixture.main(new String[]{"propose",r,proposal.toString(),"--by","agent","--by-key",agent,"--approved-by","operator","--value","42","--not-before",nb,"--not-after",na});
        // mixer1's evidence riding on mixer2's Method: the link for mixer2 names mixer2's read binding, not this one
        ProposalFixture.main(new String[]{"propose",r,cross.toString(),"--by","agent","--by-key",agent,"--approved-by","operator","--value","42","--not-before",nb,"--not-after",na,"--mixer","2","--evidence-mixer","1"});
        var refused=cli(1,"command","verify",r,cross.toString());
        assertEquals("command.link.mismatch",text(refused,"error"));assertEquals("binding.source",text(refused,"detail"));

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
