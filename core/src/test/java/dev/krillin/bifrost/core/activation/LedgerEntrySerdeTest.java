package dev.krillin.bifrost.core.activation;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class LedgerEntrySerdeTest {
    private final ObjectMapper mapper = JsonMapperFactory.create();

    private static ActivationEvent ev() {
        return new ActivationEvent("Line1","recipe","mix","1.0.0","sha","alice","bob",1000L,null,"ACTIVATE");
    }

    @Test void legacy_three_field_line_deserializes_with_null_sigs() throws Exception {
        // A T4 line has no sig fields at all.
        String legacy = "{\"event\":{\"target\":\"Line1\",\"kind\":\"recipe\",\"ref\":\"mix\",\"version\":\"1.0.0\","
                + "\"contentSha256\":\"sha\",\"activatedBy\":\"alice\",\"approvedBy\":\"bob\",\"activatedAt\":1000,"
                + "\"priorVersion\":null,\"action\":\"ACTIVATE\"},\"prevHash\":\""
                + LedgerChain.GENESIS + "\",\"entryHash\":\"deadbeef\"}";
        LedgerEntry e = mapper.readValue(legacy, LedgerEntry.class);
        assertNull(e.activatorSig());
        assertNull(e.approverSig());
        assertEquals("deadbeef", e.entryHash());
    }

    @Test void signed_entry_roundtrips_through_json() throws Exception {
        LedgerEntry signed = new LedgerEntry(ev(), LedgerChain.GENESIS, "hash1", "aSig", "bSig");
        LedgerEntry back = mapper.readValue(mapper.writeValueAsString(signed), LedgerEntry.class);
        assertEquals("aSig", back.activatorSig());
        assertEquals("bSig", back.approverSig());
    }

    @Test void entryHash_ignores_signatures() {
        // signatures are NOT in the hash preimage -> LedgerChain unaffected
        ActivationEvent e = ev();
        assertEquals(LedgerChain.entryHash(e, LedgerChain.GENESIS),
                     new LedgerEntry(e, LedgerChain.GENESIS,
                             LedgerChain.entryHash(e, LedgerChain.GENESIS), "x", "y").entryHash());
    }
}
