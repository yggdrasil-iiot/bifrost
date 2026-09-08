package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

class BridgeIdentityTest {

    @Test
    void clientIdIsDerivedFromGroupAndEdge() {
        assertEquals("heimdall-Bifrost-Line1-recipe-edge",
                NcmdOpcUaBridge.clientId("Bifrost:Line1", "recipe-edge"));
    }

    @Test
    void twoEdgesNeverShareAClientId() {
        assertNotEquals(NcmdOpcUaBridge.clientId("Bifrost:Line1", "recipe-edge"),
                        NcmdOpcUaBridge.clientId("Bifrost:Line1", "mixer-edge"));
    }

    /** A group like "Bifrost:Line1" carries separators a broker rejects in a client id. */
    @Test
    void separatorsAreFolded() {
        assertEquals("heimdall-a-b-c-d", NcmdOpcUaBridge.clientId("a/b:c", "d"));
    }
}
