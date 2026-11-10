package yggdrasil.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Stage A startup refusals in {@code NcmdOpcUaBridgeMain}: the command ledger is required (the
 * command node's bdSeq lives under it), and the effective applicationUri must match an existing
 * certificate's subjectAltName, with the override able only to carry an existing certificate.
 */
class CommandNodeStartupTest {

    private static NcmdOpcUaBridgeMain.Config config(Map<String, String> env) {
        return NcmdOpcUaBridgeMain.resolve(env::get);
    }

    private static Map<String, String> env(Object... kv) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], String.valueOf(kv[i + 1]));
        }
        return m;
    }

    @Test void command_ledger_path_is_required() {
        var e = assertThrows(IllegalStateException.class,
                () -> NcmdOpcUaBridgeMain.requireCommandLedgerPath(config(env())));
        assertTrue(e.getMessage().startsWith("command.node: COMMAND_LEDGER_PATH is required"), e.getMessage());
        assertEquals(Path.of("ledger"),
                NcmdOpcUaBridgeMain.requireCommandLedgerPath(config(env("COMMAND_LEDGER_PATH", "ledger"))));
    }

    @Test void the_default_edge_is_the_command_edge_and_its_uri_is_derived() {
        var c = config(env());
        assertEquals("recipe-edge-cmd", c.edge());
        assertEquals("urn:bifrost:heimdall:Bifrost-Line1:recipe-edge-cmd",
                NcmdOpcUaBridgeMain.effectiveApplicationUri(c));
        assertEquals("urn:x:kept", NcmdOpcUaBridgeMain.effectiveApplicationUri(
                config(env("HEIMDALL_APPLICATION_URI", "urn:x:kept"))));
    }

    @Test void no_identity_and_no_override_is_the_anonymous_path() throws Exception {
        assertNull(NcmdOpcUaBridgeMain.loadIdentity(config(env())));
    }

    @Test void a_new_identity_is_created_under_the_derived_uri(@TempDir Path dir) throws Exception {
        EdgeIdentity id = NcmdOpcUaBridgeMain.loadIdentity(config(env("HEIMDALL_IDENTITY_DIR", dir)));
        assertEquals(List.of("urn:bifrost:heimdall:Bifrost-Line1:recipe-edge-cmd"),
                EdgeIdentity.subjectAltNameUris(id.certificate()));
    }

    @Test void a_renamed_edge_over_an_old_certificate_is_a_mismatch(@TempDir Path dir) throws Exception {
        EdgeIdentity old = EdgeIdentity.loadOrCreate(dir, "urn:bifrost:heimdall:Bifrost-Line1:recipe-edge");
        var e = assertThrows(IllegalStateException.class, () -> NcmdOpcUaBridgeMain.loadIdentity(
                config(env("HEIMDALL_IDENTITY_DIR", dir, "SPB_EDGE", "recipe-edge-cmd"))));
        assertTrue(e.getMessage().startsWith("identity.uri.mismatch"), e.getMessage());
        assertTrue(e.getMessage().contains("urn:bifrost:heimdall:Bifrost-Line1:recipe-edge]"), e.getMessage());
        // Nothing was replaced: the refusal leaves the certificate the server trusts in place.
        assertEquals(old.thumbprint(), EdgeIdentity.loadOrCreate(dir, "unused").thumbprint());
    }

    @Test void the_override_keeps_an_existing_certificate_across_a_rename(@TempDir Path dir) throws Exception {
        String kept = "urn:bifrost:heimdall:Bifrost-Line1:recipe-edge";
        EdgeIdentity old = EdgeIdentity.loadOrCreate(dir, kept);
        EdgeIdentity id = NcmdOpcUaBridgeMain.loadIdentity(config(env(
                "HEIMDALL_IDENTITY_DIR", dir, "SPB_EDGE", "recipe-edge-cmd", "HEIMDALL_APPLICATION_URI", kept)));
        assertEquals(old.thumbprint(), id.thumbprint(), "same certificate, same server trust");
        assertEquals(kept, id.applicationUri());
    }

    @Test void an_override_that_differs_from_the_certificate_is_a_mismatch(@TempDir Path dir) throws Exception {
        EdgeIdentity.loadOrCreate(dir, "urn:bifrost:heimdall:Bifrost-Line1:recipe-edge");
        var e = assertThrows(IllegalStateException.class, () -> NcmdOpcUaBridgeMain.loadIdentity(config(env(
                "HEIMDALL_IDENTITY_DIR", dir, "HEIMDALL_APPLICATION_URI", "urn:x:other"))));
        assertTrue(e.getMessage().startsWith("identity.uri.mismatch"), e.getMessage());
    }

    @Test void the_override_over_an_empty_identity_directory_refuses_and_writes_nothing(@TempDir Path tmp)
            throws Exception {
        Path dir = tmp.resolve("identity");
        var e = assertThrows(IllegalStateException.class, () -> NcmdOpcUaBridgeMain.loadIdentity(config(env(
                "HEIMDALL_IDENTITY_DIR", dir, "HEIMDALL_APPLICATION_URI", "urn:x:new"))));
        assertTrue(e.getMessage().startsWith("identity.uri.override-without-certificate"), e.getMessage());
        assertFalse(EdgeIdentity.exists(dir));
        assertFalse(Files.exists(dir.resolve("edge-cert.der")), "no certificate was minted under the override");
    }

    @Test void the_override_without_an_identity_directory_refuses() {
        var e = assertThrows(IllegalStateException.class, () -> NcmdOpcUaBridgeMain.loadIdentity(
                config(env("HEIMDALL_APPLICATION_URI", "urn:x:new"))));
        assertTrue(e.getMessage().startsWith("identity.uri.override-without-certificate"), e.getMessage());
    }
}
