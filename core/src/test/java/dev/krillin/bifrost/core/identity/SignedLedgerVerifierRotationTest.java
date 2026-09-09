package dev.krillin.bifrost.core.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.krillin.bifrost.core.activation.ActivationEvent;
import dev.krillin.bifrost.core.activation.ActivationLedger;
import dev.krillin.bifrost.core.activation.LedgerSigner;

/**
 * The ledger across a key rotation.
 *
 * <p>The point of the round: entries signed with a key that has since been retired must keep
 * verifying. The ledger is append-only, so anything else would mean a rotation permanently broke the
 * target -- the same failure mode R4's break-glass design avoided, arriving by a different door.
 *
 * <p>And the hole rotation opens: four-eyes distinctness has always been enforced on KEYS, but its
 * purpose is two PEOPLE. Once one principal can hold two keys, key-distinctness stops implying
 * person-distinctness, and one person could sign both legs with two keys of their own.
 */
class SignedLedgerVerifierRotationTest {

    private static ActivationEvent ev(String v, String prior, String by, String approver) {
        return new ActivationEvent("Line1", "recipe", "mix", v, "sha-" + v, by, approver, 1000L, prior,
                "ACTIVATE");
    }

    private static String line(String principal, KeyPair kp) {
        return "{\"principal\":\"" + principal + "\",\"publicKey\":\""
                + Ed25519Keys.publicKeyB64(kp.getPublic()) + "\"}";
    }

    private static void writeAnchor(Path root, String... lines) throws Exception {
        Path akf = root.resolve("identity").resolve("authorized-keys.jsonl");
        Files.createDirectories(akf.getParent());
        List<String> all = new ArrayList<>(List.of(lines));
        Files.write(akf, all);
    }

    private static Path keyFile(Path keys, String name, KeyPair kp) throws Exception {
        Path f = keys.resolve(name);
        Files.writeString(f, Ed25519Keys.privateKeyB64(kp.getPrivate()));
        return f;
    }

    /**
     * The round's central assertion: sign with the predecessor, then register a successor, and the
     * history must still verify. Before key sets existed this could not even be set up -- writing the
     * second line threw at load.
     */
    @Test void entries_signed_with_a_retired_key_still_verify(@TempDir Path root, @TempDir Path keys)
            throws Exception {
        KeyPair aliceOld = Ed25519Keys.generate();
        KeyPair bob = Ed25519Keys.generate();
        writeAnchor(root, line("alice", aliceOld), line("bob", bob));
        LedgerSigner s = KeyFileLedgerSigner.create("alice", keyFile(keys, "a", aliceOld),
                "bob", keyFile(keys, "b", bob), AuthorizedKeys.load(root));
        ActivationLedger ledger = new ActivationLedger(root);
        ledger.append(ev("1.0.0", null, "alice", "bob"), s);
        assertTrue(SignedLedgerVerifier.forRegistry(root).verify("Line1").intact());

        // alice rotates: the successor is added, the predecessor is KEPT (deleting it is the landmine)
        KeyPair aliceNew = Ed25519Keys.generate();
        writeAnchor(root, line("alice", aliceOld), line("alice", aliceNew), line("bob", bob));

        SignedVerdict v = SignedLedgerVerifier.forRegistry(root).verify("Line1");
        assertTrue(v.intact(), "a rotation must not break the history the retired key signed: " + v.rule());
    }

    /** And the successor can sign into the same ledger, verified alongside the predecessor's entries. */
    @Test void both_keys_sign_into_one_ledger(@TempDir Path root, @TempDir Path keys) throws Exception {
        KeyPair aliceOld = Ed25519Keys.generate();
        KeyPair aliceNew = Ed25519Keys.generate();
        KeyPair bob = Ed25519Keys.generate();
        writeAnchor(root, line("alice", aliceOld), line("bob", bob));
        ActivationLedger ledger = new ActivationLedger(root);
        ledger.append(ev("1.0.0", null, "alice", "bob"),
                KeyFileLedgerSigner.create("alice", keyFile(keys, "a1", aliceOld),
                        "bob", keyFile(keys, "b", bob), AuthorizedKeys.load(root)));

        writeAnchor(root, line("alice", aliceOld), line("alice", aliceNew), line("bob", bob));
        ledger.append(ev("1.1.0", "1.0.0", "alice", "bob"),
                KeyFileLedgerSigner.create("alice", keyFile(keys, "a2", aliceNew),
                        "bob", keyFile(keys, "b", bob), AuthorizedKeys.load(root)));

        SignedVerdict v = SignedLedgerVerifier.forRegistry(root).verify("Line1");
        assertTrue(v.intact(), String.valueOf(v.rule()));
    }

    /**
     * The hole rotation opens. alice holds two keys; she signs the activator leg with one and the
     * approver leg with the other, naming herself both times. Both signatures verify and the two keys
     * differ, so a key-only distinctness check passes and four-eyes is defeated by one person.
     */
    @Test void one_person_cannot_sign_both_legs_with_two_of_their_own_keys(@TempDir Path root,
            @TempDir Path keys) throws Exception {
        KeyPair k1 = Ed25519Keys.generate();
        KeyPair k2 = Ed25519Keys.generate();
        writeAnchor(root, line("alice", k1), line("alice", k2));
        LedgerSigner s = KeyFileLedgerSigner.create("alice", keyFile(keys, "k1", k1),
                "alice", keyFile(keys, "k2", k2), AuthorizedKeys.load(root));
        new ActivationLedger(root).append(ev("1.0.0", null, "alice", "alice"), s);

        SignedVerdict v = SignedLedgerVerifier.forRegistry(root).verify("Line1");
        assertFalse(v.intact(), "two keys held by one person are not two people");
        assertEquals("identity.four-eyes.same-principal", v.rule());
    }

    /** The existing rule is unchanged: two names resolving to the same key is still caught. */
    @Test void the_same_key_under_two_names_is_still_caught(@TempDir Path root, @TempDir Path keys)
            throws Exception {
        KeyPair shared = Ed25519Keys.generate();
        writeAnchor(root, line("alice", shared), line("bob", shared));
        LedgerSigner s = KeyFileLedgerSigner.create("alice", keyFile(keys, "a", shared),
                "bob", keyFile(keys, "b", shared), AuthorizedKeys.load(root));
        new ActivationLedger(root).append(ev("1.0.0", null, "alice", "bob"), s);

        SignedVerdict v = SignedLedgerVerifier.forRegistry(root).verify("Line1");
        assertFalse(v.intact());
        assertEquals("identity.four-eyes.same-key", v.rule());
    }

    @Test void an_unregistered_principal_is_still_unregistered(@TempDir Path root, @TempDir Path keys)
            throws Exception {
        KeyPair alice = Ed25519Keys.generate();
        KeyPair bob = Ed25519Keys.generate();
        writeAnchor(root, line("alice", alice), line("bob", bob));
        LedgerSigner s = KeyFileLedgerSigner.create("alice", keyFile(keys, "a", alice),
                "bob", keyFile(keys, "b", bob), AuthorizedKeys.load(root));
        new ActivationLedger(root).append(ev("1.0.0", null, "alice", "bob"), s);

        writeAnchor(root, line("bob", bob));   // alice's line DELETED -- the landmine, still armed
        SignedVerdict v = SignedLedgerVerifier.forRegistry(root).verify("Line1");
        assertFalse(v.intact());
        assertEquals("identity.key.unregistered", v.rule(),
                "rotation gives retirement a safe path; deleting a line is still fatal");
    }

    /** A signature no registered key of the principal verifies is invalid, not unregistered. */
    @Test void a_signature_no_key_verifies_is_sig_invalid(@TempDir Path root, @TempDir Path keys)
            throws Exception {
        KeyPair alice = Ed25519Keys.generate();
        KeyPair bob = Ed25519Keys.generate();
        writeAnchor(root, line("alice", alice), line("bob", bob));
        LedgerSigner s = KeyFileLedgerSigner.create("alice", keyFile(keys, "a", alice),
                "bob", keyFile(keys, "b", bob), AuthorizedKeys.load(root));
        new ActivationLedger(root).append(ev("1.0.0", null, "alice", "bob"), s);

        // replace alice's key with an unrelated one: registered, but nothing she signed verifies
        writeAnchor(root, line("alice", Ed25519Keys.generate()), line("bob", bob));
        SignedVerdict v = SignedLedgerVerifier.forRegistry(root).verify("Line1");
        assertFalse(v.intact());
        assertEquals("identity.sig.invalid", v.rule());
    }
}
