package dev.krillin.bifrost.gates;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
class MappingGateTest {
    @Test void wireJSONAlwaysUsesUTF8() throws Exception {
        PrintStream old=System.out;ByteArrayOutputStream sink=new ByteArrayOutputStream();
        try{System.setOut(new PrintStream(sink,true,StandardCharsets.ISO_8859_1));MappingGate.emit(object().put("note","압력 정의 확인"));}
        finally{System.setOut(old);}
        assertEquals("압력 정의 확인",JSON.readTree(sink.toByteArray()).path("note").asText());
    }
    @Test void dispatcherRoutesMappingAndReturnsCodedRefusal(@TempDir Path dir) throws Exception {
        PrintStream old=System.out;ByteArrayOutputStream sink=new ByteArrayOutputStream();int code;
        try{System.setOut(new PrintStream(sink));code=GatesCli.run(new String[]{"mapping","validate",dir.toString()});}
        finally{System.setOut(old);}
        assertEquals(1,code);assertFalse(JSON.readTree(sink.toByteArray()).path("accepted").asBoolean());assertEquals("excluded",JSON.readTree(sink.toByteArray()).path("execution").asText());
    }
    static com.fasterxml.jackson.databind.JsonNode cli(int expected,String... args) throws Exception {
        PrintStream old=System.out;ByteArrayOutputStream sink=new ByteArrayOutputStream();int code;
        try{System.setOut(new PrintStream(sink));code=GatesCli.run(args);}finally{System.setOut(old);}
        assertEquals(expected,code,sink.toString(StandardCharsets.UTF_8));return JSON.readTree(sink.toByteArray());
    }
    /** publish with two keys signs the head; verify-head reads it back; a swapped head is a coded refusal. */
    @Test void signedPublishAndVerifyHeadThroughTheCli(@TempDir Path dir) throws Exception {
        Path fixture=Path.of("../core/src/test/resources/mapping-fixtures/valid");assertTrue(java.nio.file.Files.isDirectory(fixture),"core mapping fixture");
        Path bundle=dir.resolve("bundle");try(var walk=java.nio.file.Files.walk(fixture)){for(Path p:walk.toList()){Path t=bundle.resolve(fixture.relativize(p).toString());if(java.nio.file.Files.isDirectory(p))java.nio.file.Files.createDirectories(t);else java.nio.file.Files.copy(p,t);}}
        Path reg=dir.resolve("registry"),keys=dir.resolve("keys");java.nio.file.Files.createDirectories(reg.resolve("identity"));
        StringBuilder pub=new StringBuilder();
        for(String who:new String[]{"proposer","approver"}){
            PrintStream old=System.out;ByteArrayOutputStream sink=new ByteArrayOutputStream();
            try{System.setOut(new PrintStream(sink));assertEquals(0,IdentityGate.run(new String[]{"keygen",who,"--out",keys.toString()}));}finally{System.setOut(old);}
            pub.append(sink.toString(StandardCharsets.UTF_8).strip()).append('\n');
        }
        java.nio.file.Files.writeString(reg.resolve("identity/authorized-keys.jsonl"),pub.toString());
        java.nio.file.Files.writeString(reg.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"p\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"mixed-line\"},{\"id\":\"a\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"mixed-line\"}]}");
        String pk=keys.resolve("proposer.key").toString(),ak=keys.resolve("approver.key").toString(),r=reg.toString();
        cli(0,"mapping","approve",r,bundle.toString(),"approval-1","--by","proposer","--by-key",pk,"--approved-by","approver","--approved-by-key",ak);
        cli(2,"mapping","publish",r,bundle.toString(),"release","1.0.0","--approval","approval-1","--by","proposer");
        cli(0,"mapping","publish",r,bundle.toString(),"release","1.0.0","--approval","approval-1","--by","proposer","--by-key",pk,"--approved-by","approver","--approved-by-key",ak,"--expires-in","P30D");
        var verified=cli(0,"mapping","verify-head",r,"mixed-line");
        assertEquals("mapping-head-verification",text(verified,"kind"));assertEquals(1,verified.path("headVersion").asInt());
        java.nio.file.Files.writeString(reg.resolve("mappings/heads/mixed-line.json"),"{\"id\":\"release\",\"sha256\":\""+"0".repeat(64)+"\",\"version\":\"1.0.0\"}");
        assertTrue(text(cli(1,"mapping","verify-head",r,"mixed-line"),"error").startsWith("mapping.release-digest"));
    }
}
