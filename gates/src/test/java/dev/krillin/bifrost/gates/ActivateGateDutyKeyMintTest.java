package dev.krillin.bifrost.gates;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.krillin.bifrost.core.identity.AuthorizedKeys;
import dev.krillin.bifrost.core.identity.Ed25519Keys;
import dev.krillin.bifrost.core.identity.KeyFileLedgerSigner;

/**
 * Minting a break-glass duty key. The four-eyes of an emergency activation happens HERE, ahead of the
 * emergency: two registered people must both present a bound key to bring a duty key into existence.
 * Afterwards one person can activate with their own key plus the duty key, and the record says
 * BREAK_GLASS because the duty principal holds no APPROVE grant.
 *
 * <p>The mint writes no ledger entry — the two-person rule is enforced by demanding two bound keys,
 * not by an audit trail — and the command must say so rather than let an operator assume otherwise.
 */
class ActivateGateDutyKeyMintTest {

    /** Registry with alice + bob registered; their key files land in {@code keys}. */
    private void registry(Path reg, Path keys) throws Exception {
        KeyPair alice = Ed25519Keys.generate();
        KeyPair bob = Ed25519Keys.generate();
        Path akf = reg.resolve("identity").resolve("authorized-keys.jsonl");
        Files.createDirectories(akf.getParent());
        Files.writeString(akf,
                "{\"principal\":\"alice\",\"publicKey\":\"" + Ed25519Keys.publicKeyB64(alice.getPublic()) + "\"}\n"
              + "{\"principal\":\"bob\",\"publicKey\":\"" + Ed25519Keys.publicKeyB64(bob.getPublic()) + "\"}\n");
        Files.writeString(keys.resolve("alice.key"), Ed25519Keys.privateKeyB64(alice.getPrivate()));
        Files.writeString(keys.resolve("bob.key"), Ed25519Keys.privateKeyB64(bob.getPrivate()));
    }

    private static String[] mint(Path reg, Path out, String principal, String by, String byKey,
                                 String approvedBy, String approvedByKey) {
        return new String[]{"activation", "duty-key-mint", reg.toString(), principal, "--out", out.toString(),
                "--by", by, "--by-key", byKey, "--approved-by", approvedBy, "--approved-by-key", approvedByKey};
    }

    /** Run the gate capturing stdout, so the printed operator instructions can be asserted. */
    private static String run(int expected, String[] args) {
        PrintStream saved = System.out;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try {
            System.setOut(new PrintStream(buf, true, StandardCharsets.UTF_8));
            assertEquals(expected, ActivateGate.run(args));
        } finally {
            System.setOut(saved);
        }
        return buf.toString(StandardCharsets.UTF_8);
    }

    // ----- four-eyes at mint time -----

    @Test void one_key_file_used_twice_is_refused(@TempDir Path reg, @TempDir Path keys, @TempDir Path out)
            throws Exception {
        registry(reg, keys);
        String o = run(1, mint(reg, out, "breakglass-line1", "alice", keys.resolve("alice.key").toString(),
                "bob", keys.resolve("alice.key").toString()));
        assertTrue(o.contains("identity.key.principal-mismatch"), o);
        assertFalse(Files.exists(out.resolve("breakglass-line1.key")), "no duty key on a refused mint");
    }

    @Test void the_same_principal_twice_is_refused(@TempDir Path reg, @TempDir Path keys, @TempDir Path out)
            throws Exception {
        registry(reg, keys);
        String o = run(1, mint(reg, out, "breakglass-line1", "alice", keys.resolve("alice.key").toString(),
                "alice", keys.resolve("alice.key").toString()));
        assertTrue(o.contains("identity.four-eyes.same-key"), o);
        assertFalse(Files.exists(out.resolve("breakglass-line1.key")));
    }

    @Test void an_unregistered_minter_is_refused(@TempDir Path reg, @TempDir Path keys, @TempDir Path out)
            throws Exception {
        registry(reg, keys);
        String o = run(1, mint(reg, out, "breakglass-line1", "alice", keys.resolve("alice.key").toString(),
                "stranger", keys.resolve("bob.key").toString()));
        assertTrue(o.contains("identity.key.principal-mismatch"), o);
        assertFalse(Files.exists(out.resolve("breakglass-line1.key")));
    }

    /**
     * Appending a second line for a principal that already has one makes {@code AuthorizedKeys.load}
     * throw — every verification, and the edge with it, would stop. Refuse at mint instead.
     */
    @Test void minting_over_an_already_registered_principal_is_refused(@TempDir Path reg, @TempDir Path keys,
            @TempDir Path out) throws Exception {
        registry(reg, keys);
        String o = run(1, mint(reg, out, "bob", "alice", keys.resolve("alice.key").toString(),
                "bob", keys.resolve("bob.key").toString()));
        assertTrue(o.contains("identity.principal.already-registered"), o);
        assertFalse(Files.exists(out.resolve("bob.key")), "an existing principal's key must not be overwritten");
    }

    // ----- the mint itself -----

    @Test void a_valid_mint_writes_a_usable_duty_keypair(@TempDir Path reg, @TempDir Path keys, @TempDir Path out)
            throws Exception {
        registry(reg, keys);
        run(0, mint(reg, out, "breakglass-line1", "alice", keys.resolve("alice.key").toString(),
                "bob", keys.resolve("bob.key").toString()));
        assertTrue(Files.isRegularFile(out.resolve("breakglass-line1.key")));
        assertTrue(Files.isRegularFile(out.resolve("breakglass-line1.pub")));
        var priv = Ed25519Keys.privateKey(Files.readString(out.resolve("breakglass-line1.key")).strip());
        var pub = Ed25519Keys.publicKey(Files.readString(out.resolve("breakglass-line1.pub")).strip());
        assertTrue(Ed25519Keys.verify("m".getBytes(StandardCharsets.UTF_8),
                Ed25519Keys.sign("m".getBytes(StandardCharsets.UTF_8), priv), pub));
    }

    /** The printed line, pasted into authorized-keys.jsonl, must actually bind the minted key file. */
    @Test void the_printed_line_registers_the_key_it_minted(@TempDir Path reg, @TempDir Path keys,
            @TempDir Path out) throws Exception {
        registry(reg, keys);
        String o = run(0, mint(reg, out, "breakglass-line1", "alice", keys.resolve("alice.key").toString(),
                "bob", keys.resolve("bob.key").toString()));
        String line = o.lines().filter(l -> l.startsWith("{\"principal\"")).findFirst().orElseThrow();
        Path akf = reg.resolve("identity").resolve("authorized-keys.jsonl");
        Files.writeString(akf, line + "\n", java.nio.file.StandardOpenOption.APPEND);
        var signer = KeyFileLedgerSigner.create("alice", keys.resolve("alice.key"),
                "breakglass-line1", out.resolve("breakglass-line1.key"), AuthorizedKeys.load(reg));
        assertEquals(java.util.List.of(), signer.preflight(),
                "the duty key must bind to the principal the printed line registers");
    }

    @Test void it_prints_the_policy_grants_the_operator_must_add(@TempDir Path reg, @TempDir Path keys,
            @TempDir Path out) throws Exception {
        registry(reg, keys);
        String o = run(0, mint(reg, out, "breakglass-line1", "alice", keys.resolve("alice.key").toString(),
                "bob", keys.resolve("bob.key").toString()));
        assertTrue(o.contains("BREAK_GLASS_APPROVE"), o);
        assertTrue(o.contains("breakglass-line1"), o);
        assertFalse(o.contains("\"action\": \"APPROVE\"") || o.contains("action=APPROVE"),
                "suggesting an APPROVE grant would let the duty key write an unmarked activation");
    }

    /** The mint writes no ledger entry, and an operator must not be left to assume it did. */
    @Test void it_says_the_mint_is_not_recorded_in_the_ledger(@TempDir Path reg, @TempDir Path keys,
            @TempDir Path out) throws Exception {
        registry(reg, keys);
        String o = run(0, mint(reg, out, "breakglass-line1", "alice", keys.resolve("alice.key").toString(),
                "bob", keys.resolve("bob.key").toString()));
        assertTrue(o.toLowerCase(java.util.Locale.ROOT).contains("not recorded in the ledger"), o);
    }

    // ----- usage -----

    @Test void missing_arguments_are_usage_errors(@TempDir Path reg, @TempDir Path keys, @TempDir Path out)
            throws Exception {
        registry(reg, keys);
        assertEquals(2, ActivateGate.run(new String[]{"activation", "duty-key-mint"}));
        assertEquals(2, ActivateGate.run(new String[]{"activation", "duty-key-mint", reg.toString(), "d"}));
        // --out present but the minters are not
        assertEquals(2, ActivateGate.run(new String[]{"activation", "duty-key-mint", reg.toString(), "d",
                "--out", out.toString()}));
    }

    @Test void a_traversing_principal_is_refused(@TempDir Path reg, @TempDir Path keys, @TempDir Path out)
            throws Exception {
        registry(reg, keys);
        assertEquals(2, ActivateGate.run(mint(reg, out, "../../evil", "alice",
                keys.resolve("alice.key").toString(), "bob", keys.resolve("bob.key").toString())));
        assertTrue(Files.notExists(out.getParent().getParent().resolve("evil.key")));
    }

    /** The pre-existing subcommand must keep working through the same switch. */
    @Test void verify_chain_still_dispatches(@TempDir Path reg) {
        assertEquals(2, ActivateGate.run(new String[]{"activation", "verify-chain", reg.toString(), "Line1"}),
                "no such target ledger is still a usage-class exit");
    }
}
