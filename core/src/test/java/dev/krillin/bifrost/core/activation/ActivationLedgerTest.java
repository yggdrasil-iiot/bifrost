package dev.krillin.bifrost.core.activation;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ActivationLedgerTest {
    static ActivationEvent ev(String ref,String ver,String action){
        return new ActivationEvent("Line1","recipe",ref,ver,"sha","alice","bob",1L,null,action);
    }
    @Test void appendActiveHistory(@TempDir Path reg) throws Exception {
        ActivationLedger led = new ActivationLedger(reg);
        assertTrue(led.active("Line1","recipe","mix-recipe").isEmpty());
        led.append(ev("mix-recipe","1.0.0","ACTIVATE"));
        led.append(ev("other","5.0.0","ACTIVATE"));
        led.append(ev("mix-recipe","1.1.0","ACTIVATE"));
        assertEquals("1.1.0", led.active("Line1","recipe","mix-recipe").orElseThrow().version());
        assertEquals("5.0.0", led.active("Line1","recipe","other").orElseThrow().version());
        assertEquals(3, led.history("Line1").size());
        assertEquals("1.0.0", led.history("Line1").get(0).version());
    }
    @Test void missingTargetIsEmpty(@TempDir Path reg) throws Exception {
        assertTrue(new ActivationLedger(reg).history("Nope").isEmpty());
    }
}
