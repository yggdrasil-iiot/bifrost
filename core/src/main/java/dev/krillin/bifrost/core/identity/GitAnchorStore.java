package dev.krillin.bifrost.core.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.activation.AnchorRecord;
import dev.krillin.bifrost.core.activation.AnchorStore;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/** OPT-IN git-backed {@link AnchorStore}: the anchor's entire defensive value is that {@link #latest}
 *  reads the record from COMMITTED git history ({@code git show HEAD:<file>}), NEVER the mutable working
 *  tree — so it survives a working-tree co-rollback that a plain {@link dev.krillin.bifrost.core.activation.FileAnchorStore}
 *  cannot detect (the AN4 witness property, spec §5). Pure JDK: shells out to {@code git} via
 *  {@link ProcessBuilder} (no JGit / no new Maven dependency). Instantiated ONLY by config (gate/Heimdall),
 *  never on core's default path. Single control-plane writer (no concurrency). */
public final class GitAnchorStore implements AnchorStore {
    private final Path anchorRepo;
    private final ObjectMapper mapper = JsonMapperFactory.create();

    /** The directory becomes a git repo: if {@code <anchorRepo>/.git} is absent, {@code git init} runs and
     *  a LOCAL commit identity is set so commits work in a clean env. Throws
     *  {@code anchor.git.unavailable} if {@code git} cannot be run at all. */
    public GitAnchorStore(Path anchorRepo) {
        this.anchorRepo = anchorRepo;
        try {
            Files.createDirectories(anchorRepo);
        } catch (IOException e) {
            throw new IllegalStateException("anchor.git.init-failed: " + e.getMessage(), e);
        }
        if (!Files.isDirectory(anchorRepo.resolve(".git"))) {
            requireOk(runGit("init"), "init");
            requireOk(runGit("config", "user.email", "anchor@bifrost.local"), "config");
            requireOk(runGit("config", "user.name", "bifrost-anchor"), "config");
        }
    }

    private String anchorFile(String target) { return target + ".anchor.jsonl"; }

    /** Reads the anchor from the COMMITTED HEAD ({@code git show HEAD:<file>}), never the working tree.
     *  Returns empty when the repo has no commits yet (no HEAD) or the path is absent at HEAD — both make
     *  {@code git show} exit non-zero, which is treated as "never anchored", not an error. */
    @Override public Optional<AnchorRecord> latest(String target) throws IOException {
        GitResult r = runGit("show", "HEAD:" + anchorFile(target));
        if (r.exit != 0) return Optional.empty();   // no HEAD, or path missing at HEAD → never anchored
        AnchorRecord last = null;
        for (String line : r.stdout.split("\n", -1))
            if (!line.isBlank()) last = mapper.readValue(line, AnchorRecord.class);
        return Optional.ofNullable(last);
    }

    /** Enforces the same monotonic contract as FileAnchorStore against the COMMITTED latest, then appends
     *  the record to the working-tree file and commits it (so the next {@link #latest} witnesses it). */
    @Override public void record(AnchorRecord r) throws IOException {
        Optional<AnchorRecord> cur = latest(r.target());
        if (cur.isPresent()) {
            AnchorRecord l = cur.get();
            if (r.seq() == l.seq()) {
                if (!r.tailEntryHash().equals(l.tailEntryHash()))
                    throw new IllegalStateException("anchor.same-seq-conflict: target=" + r.target()
                            + " seq=" + r.seq() + " tail " + r.tailEntryHash() + " != " + l.tailEntryHash());
                return;   // idempotent no-op — no commit
            }
            if (r.seq() < l.seq())
                throw new IllegalStateException("anchor.seq-regression: target=" + r.target()
                        + " new seq=" + r.seq() + " < latest seq=" + l.seq());
        }
        String file = anchorFile(r.target());
        Files.writeString(anchorRepo.resolve(file), mapper.writeValueAsString(r) + "\n",
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        requireOk(runGit("add", file), "add");
        requireOk(runGit("commit", "-m", "anchor " + r.target() + " seq=" + r.seq()), "commit");
    }

    // ---- git process plumbing -------------------------------------------------------------------

    private record GitResult(int exit, String stdout, String stderr) {}

    private void requireOk(GitResult r, String op) {
        if (r.exit() != 0)
            throw new IllegalStateException("anchor.git." + op + "-failed: " + r.stderr());
    }

    /** Runs {@code git <args>} with the repo as working dir, capturing stdout, stderr and the exit code.
     *  stderr is drained on a separate thread so a full stderr pipe can never deadlock the stdout read.
     *  A failure to even start {@code git} means it is not runnable → {@code anchor.git.unavailable}. */
    private GitResult runGit(String... args) {
        List<String> cmd = new ArrayList<>();
        cmd.add("git");
        Collections.addAll(cmd, args);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(anchorRepo.toFile());
        pb.redirectErrorStream(false);
        Process p;
        try {
            p = pb.start();
        } catch (IOException e) {
            throw new IllegalStateException("anchor.git.unavailable", e);
        }
        StringBuilder err = new StringBuilder();
        Thread errDrain = new Thread(() -> {
            try {
                err.append(new String(p.getErrorStream().readAllBytes(), StandardCharsets.UTF_8));
            } catch (IOException ignored) { /* best-effort diagnostic capture */ }
        });
        errDrain.start();
        byte[] out;
        try {
            out = p.getInputStream().readAllBytes();
            int exit = p.waitFor();
            errDrain.join();
            return new GitResult(exit, new String(out, StandardCharsets.UTF_8), err.toString().strip());
        } catch (IOException e) {
            throw new IllegalStateException("anchor.git.unavailable", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("anchor.git.unavailable", e);
        }
    }
}
