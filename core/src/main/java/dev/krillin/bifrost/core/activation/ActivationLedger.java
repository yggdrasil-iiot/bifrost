package dev.krillin.bifrost.core.activation;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/** Append-only JSONL audit ledger at registry/activation/<target>.jsonl. The LAST event per (kind,ref)
 *  is the current active pointer. Single control-plane writer (no concurrent-writer coordination). */
public final class ActivationLedger {
    private final Path root;
    private final ObjectMapper mapper = JsonMapperFactory.create();
    public ActivationLedger(Path registryRoot) { this.root = registryRoot; }

    private Path file(String target) { return root.resolve("activation").resolve(target + ".jsonl"); }

    public void append(ActivationEvent e) throws IOException {
        Path f = file(e.target());
        Files.createDirectories(f.getParent());
        String prevHash = tailEntryHash(f);
        LedgerEntry entry = new LedgerEntry(e, prevHash, LedgerChain.entryHash(e, prevHash));
        Files.writeString(f, mapper.writeValueAsString(entry) + "\n",
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    /** The prevHash for the next append = the last entry's entryHash (GENESIS if the ledger is empty).
     *  Reads the file tail only; does NOT re-verify the whole chain on every append (spec §7). */
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
