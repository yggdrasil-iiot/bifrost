package dev.krillin.bifrost.core.activation;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import java.io.IOException;
import java.nio.file.*;
import java.util.Optional;

/** Pure-JDK append-only anchor witness at registry/anchor/<target>.anchor.jsonl, one AnchorRecord per
 *  line, latest = last line. This is the LOCAL PROJECTION of the off-box witness — on its own it does
 *  NOT defend against a co-rollback that also rolls back this file (see spec §5). The real witness is
 *  GitAnchorStore committed to a protected remote. Single control-plane writer (no concurrency). */
public final class FileAnchorStore implements AnchorStore {
    private final Path root;
    private final ObjectMapper mapper = JsonMapperFactory.create();

    public FileAnchorStore(Path registryRoot) { this.root = registryRoot; }

    private Path file(String target) { return root.resolve("anchor").resolve(target + ".anchor.jsonl"); }

    @Override public Optional<AnchorRecord> latest(String target) throws IOException {
        Path f = file(target);
        if (!Files.isRegularFile(f)) return Optional.empty();
        AnchorRecord last = null;
        for (String line : Files.readAllLines(f))
            if (!line.isBlank()) last = mapper.readValue(line, AnchorRecord.class);
        return Optional.ofNullable(last);
    }

    @Override public void record(AnchorRecord r) throws IOException {
        Optional<AnchorRecord> cur = latest(r.target());
        if (cur.isPresent()) {
            AnchorRecord l = cur.get();
            if (r.seq() == l.seq()) {
                if (!r.tailEntryHash().equals(l.tailEntryHash()))
                    throw new IllegalStateException("anchor.same-seq-conflict: target=" + r.target()
                            + " seq=" + r.seq() + " tail " + r.tailEntryHash() + " != " + l.tailEntryHash());
                return;   // idempotent no-op
            }
            if (r.seq() < l.seq())
                throw new IllegalStateException("anchor.seq-regression: target=" + r.target()
                        + " new seq=" + r.seq() + " < latest seq=" + l.seq());
        }
        Path f = file(r.target());
        Files.createDirectories(f.getParent());
        Files.writeString(f, mapper.writeValueAsString(r) + "\n",
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }
}
