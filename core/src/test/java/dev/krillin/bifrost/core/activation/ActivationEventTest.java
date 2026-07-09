package dev.krillin.bifrost.core.activation;
import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import org.junit.jupiter.api.Test;

class ActivationEventTest {
    @Test void jsonRoundTrips() throws Exception {
        ObjectMapper m = JsonMapperFactory.create();
        ActivationEvent e = new ActivationEvent("Line1","recipe","mix-recipe","1.1.0",
            "abc123","alice","bob",1720000000000L,"1.0.0","ACTIVATE");
        String line = m.writeValueAsString(e);
        assertFalse(line.contains("\n"));                       // single JSONL line
        assertEquals(e, m.readValue(line, ActivationEvent.class));
    }
    @Test void sha256IsStableHex() {
        assertEquals(Sha256.hex("hello".getBytes()),
                     "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }
}
