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
}
