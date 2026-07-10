package dev.krillin.bifrost.core.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import java.io.IOException;
import java.nio.file.*;
import java.util.Optional;

/** Reads/writes registry/identity/<target>.head. The head preimage is a canonical, delimiter-joined
 *  field concat (NOT JSON) - target U+001F seq U+001F tailEntryHash - so the writer and every verifier
 *  sign/verify byte-for-byte identical input (same discipline as LedgerChain.preimage). */
public final class SignedHeadStore {
    private static final char SEP = '\u001F';   // U+001F Unit Separator
    private final Path root;
    private final ObjectMapper mapper = JsonMapperFactory.create();

    public SignedHeadStore(Path registryRoot) { this.root = registryRoot; }

    private Path file(String target) { return root.resolve("identity").resolve(target + ".head"); }

    /** The signed bytes' textual preimage. Kept identical between writer and verifier. */
    public static String preimage(String target, long seq, String tailEntryHash) {
        return target + SEP + seq + SEP + tailEntryHash;
    }

    public Optional<SignedHead> read(String target) throws IOException {
        Path f = file(target);
        if (!Files.isRegularFile(f)) return Optional.empty();
        String content = Files.readString(f).strip();
        if (content.isEmpty()) return Optional.empty();
        return Optional.of(mapper.readValue(content, SignedHead.class));
    }

    public void write(SignedHead head) throws IOException {
        Path f = file(head.target());
        Files.createDirectories(f.getParent());
        Files.writeString(f, mapper.writeValueAsString(head) + "\n",
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
    }
}
