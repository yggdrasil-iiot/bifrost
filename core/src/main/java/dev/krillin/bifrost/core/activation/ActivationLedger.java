package dev.krillin.bifrost.core.activation;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/** Append-only, hash-chained JSONL audit ledger at registry/activation/<target>.jsonl. Each line is a
 *  {@link LedgerEntry} (event + prevHash + entryHash) linking to the prior line, so the whole target
 *  history is tamper-evident (see {@link LedgerChain}). The LAST event per (kind,ref) is the current
 *  active pointer. Single control-plane writer (no concurrent-writer coordination).
 *  Line shape is LedgerEntry, not a flat ActivationEvent — registries are gate-regenerated, so there is
 *  no legacy flat-line data to migrate (a legacy flat line would fail to parse; see spec §9). */
public final class ActivationLedger {
    private final Path root;
    private final ObjectMapper mapper = JsonMapperFactory.create();
    private final dev.krillin.bifrost.core.identity.SignedHeadStore heads;
    private final AnchorStore anchors;
    public ActivationLedger(Path registryRoot) { this(registryRoot, null); }
    public ActivationLedger(Path registryRoot, AnchorStore anchors) {
        this.root = registryRoot;
        this.heads = new dev.krillin.bifrost.core.identity.SignedHeadStore(registryRoot);
        this.anchors = anchors;
    }

    private Path file(String target) { return root.resolve("activation").resolve(target + ".jsonl"); }

    /** T4-compatible unsigned append. */
    public void append(ActivationEvent e) throws IOException { append(e, null); }

    /** T5: when signer != null, dual-sign the entry over entryHash and advance the signed head; when null,
     *  exact T4 behavior (unsigned line, no head). Write order is ledger line → dual head → anchor — a
     *  crash between line and head leaves head.seq one behind, caught fail-closed by SignedLedgerVerifier
     *  (spec §7); the anchor is recorded LAST so it never witnesses a seq the head hasn't reached. */
    public void append(ActivationEvent e, LedgerSigner signer) throws IOException {
        Path f = file(e.target());
        Files.createDirectories(f.getParent());
        String prevHash = tailEntryHash(f);
        String entryHash = LedgerChain.entryHash(e, prevHash);
        LedgerEntry entry = (signer == null)
                ? LedgerEntry.unsigned(e, prevHash, entryHash)
                : signedEntry(e, prevHash, entryHash, signer);
        Files.writeString(f, mapper.writeValueAsString(entry) + "\n",
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        if (signer != null) advanceHead(e.target(), entryHash, signer);
    }

    private LedgerEntry signedEntry(ActivationEvent e, String prevHash, String entryHash,
                                    LedgerSigner signer) {
        Signatures sig = signer.sign(entryHash);
        return new LedgerEntry(e, prevHash, entryHash, sig.activatorSig(), sig.approverSig());
    }

    private void advanceHead(String target, String tailEntryHash, LedgerSigner signer) throws IOException {
        // seq source of truth is the HEAD file, not history length: deleting the head then appending once
        // wedges the target into head.seq-mismatch at verify time (fail-closed, by design — spec §7).
        long seq = heads.read(target).map(h -> h.seq() + 1).orElse(0L);
        String preimage = dev.krillin.bifrost.core.identity.SignedHeadStore.preimage(target, seq, tailEntryHash);
        HeadSignatures hs = signer.signHead(preimage);
        heads.write(new dev.krillin.bifrost.core.identity.SignedHead(
                target, seq, tailEntryHash, signer.approverPrincipal(), hs.approverSig(),
                signer.activatorPrincipal(), hs.activatorSig()));
        if (anchors != null) anchors.record(new AnchorRecord(target, seq, tailEntryHash));  // last = the catch-up witness
    }

    /** The prevHash for the next append = the last entry's entryHash (GENESIS if the ledger is empty).
     *  Reads the whole file to take the last non-blank line (O(n) read), but does NOT re-verify the chain
     *  per append — a pre-existing break is caught by verifyChain / the Heimdall edge, not here (spec §7). */
    private String tailEntryHash(Path f) throws IOException {
        if (!Files.isRegularFile(f)) return LedgerChain.GENESIS;
        String last = null;
        for (String line : Files.readAllLines(f)) if (!line.isBlank()) last = line;
        return last == null ? LedgerChain.GENESIS : mapper.readValue(last, LedgerEntry.class).entryHash();
    }

    public List<LedgerEntry> history(String target) throws IOException {
        Path f = file(target);
        if (!Files.isRegularFile(f)) return List.of();
        List<LedgerEntry> out = new ArrayList<>();
        for (String line : Files.readAllLines(f)) {
            if (!line.isBlank()) out.add(mapper.readValue(line, LedgerEntry.class));
        }
        return out;
    }

    public Optional<ActivationEvent> active(String target, String kind, String ref) throws IOException {
        ActivationEvent found = null;
        for (LedgerEntry en : history(target)) {
            ActivationEvent e = en.event();
            if (e.kind().equals(kind) && e.ref().equals(ref)) found = e;   // last match wins
        }
        return Optional.ofNullable(found);
    }

    public ChainVerdict verifyChain(String target) throws IOException {
        return LedgerChain.verify(history(target));
    }
}
