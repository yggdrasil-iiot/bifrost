package yggdrasil.bifrost.core.command;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;

import yggdrasil.bifrost.core.schema.JsonMapperFactory;

/**
 * The append-only, hash-chained record of runtime commands, segmented one file per UTC day per edge.
 *
 * <p><b>{@code append} is synchronized, and that is not defensive.</b> It reads the segment's tail
 * hash and then writes — a read-modify-write. R0 spread the apply path across four
 * {@code CommandExecutor} stripes, so two commands genuinely arrive at once; without the lock they
 * produce two entries claiming the same {@code prevHash}, a chain broken by the ledger itself. The
 * activation ledger's equivalent is unsynchronized because roughly ten activations a day arrive from
 * one writer; commands are not that.
 *
 * <p><b>Segments are linked, not restarted.</b> A new day's first entry carries the previous
 * segment's tail hash. Restarting each segment at {@link CommandChain#GENESIS} would let any
 * segment — including the current one — be deleted or rewritten end to end with nothing to
 * contradict it, which is materially weaker than the activation ledger's single chain.
 *
 * <p><b>The clock is injected</b> because a segment boundary that only the wall clock can cross is a
 * boundary no test can drive.
 *
 * <p><b>A Method command's intent is also its replay reservation.</b> {@link #reserve} checks for an
 * earlier reservation of the same {@code cmdId} and appends the new one under the same lock, then
 * forces it to disk before returning, so a reservation the edge acted on survives a crash or a
 * restart. Only an intent whose outcome is {@link #RESERVED} reserves; a refusal recorded for audit
 * does not.
 *
 * <p>What this does not do: sign anything, and therefore detect truncation. See {@link CommandChain}.
 */
public final class CommandLedger {

    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("yyyy-MM-dd");

    /** The intent outcome that reserves a Method command's {@code cmdId}. */
    public static final String RESERVED = "reserved";

    private final Path root;
    private final Clock clock;
    private final ObjectMapper mapper = JsonMapperFactory.create();

    public CommandLedger(Path root, Clock clock) {
        this.root = root;
        this.clock = clock;
    }

    /** {@code <root>/commands/<group>/<edge>/<yyyy-MM-dd>.jsonl}, group/edge folded for the filesystem. */
    public Path segment(String group, String edge) {
        String day = DAY.format(clock.instant().atZone(ZoneOffset.UTC));
        return root.resolve("commands").resolve(safe(group)).resolve(safe(edge)).resolve(day + ".jsonl");
    }

    /**
     * Append one event, linked to whatever this edge's chain currently ends with.
     *
     * @throws IOException when the entry could not be persisted — the caller decides what that means,
     *                     and for an intent entry the edge refuses the command rather than touching
     *                     the plant unrecorded.
     */
    public synchronized void append(CommandEvent e) throws IOException {
        write(e, false);
    }

    /**
     * Reserve a Method command's {@code cmdId}: refuse when this edge already holds a reservation for
     * it in any segment from {@code from}'s day through today, otherwise append the intent and force
     * it to disk. The check and the append share this object's lock, so two deliveries of one command
     * cannot both reserve it.
     *
     * @param e    an intent whose outcome is {@link #RESERVED}
     * @param from the earliest instant a reservation for this command could carry - the start of its
     *             validity window
     * @return false when the {@code cmdId} was already reserved; nothing is written then
     * @throws IOException when the segments cannot be read or the entry cannot be made durable
     */
    public synchronized boolean reserve(CommandEvent e, Instant from) throws IOException {
        if (!CommandEvent.INTENT.equals(e.phase()) || !RESERVED.equals(e.outcome()) || e.cmdId() == null) {
            throw new IllegalArgumentException("a reservation is an intent with outcome " + RESERVED + " and a cmdId");
        }
        if (reserved(e.group(), e.edge(), e.cmdId(), from)) {
            return false;
        }
        write(e, true);
        return true;
    }

    /**
     * Whether this edge holds a reservation for {@code cmdId} in any segment from {@code from}'s day
     * through today. An unparseable line is an IOException rather than the end of the scan: a
     * reservation hidden behind it must not read as absent.
     */
    public synchronized boolean reserved(String group, String edge, String cmdId, Instant from) throws IOException {
        Path seg = segment(group, edge);
        Path dir = seg.getParent();
        if (dir == null || !Files.isDirectory(dir)) {
            return false;
        }
        String first = DAY.format(from.atZone(ZoneOffset.UTC)) + ".jsonl";
        String last = seg.getFileName().toString();
        List<Path> segments;
        try (var stream = Files.list(dir)) {
            segments = stream.filter(p -> {
                String n = p.getFileName().toString();
                return n.endsWith(".jsonl") && n.compareTo(first) >= 0 && n.compareTo(last) <= 0;
            }).sorted().toList();
        }
        for (Path p : segments) {
            List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);
            for (int i = 0; i < lines.size(); i++) {
                if (lines.get(i).isBlank()) {
                    continue;
                }
                CommandEvent ev;
                try {
                    ev = mapper.readValue(lines.get(i), CommandLedgerEntry.class).event();
                } catch (Exception malformed) {
                    throw new IOException("unparseable entry at " + p.getFileName() + ":" + i, malformed);
                }
                if (CommandEvent.INTENT.equals(ev.phase()) && RESERVED.equals(ev.outcome()) && cmdId.equals(ev.cmdId())) {
                    return true;
                }
            }
        }
        return false;
    }

    /** One linked entry; {@code durable} forces the segment to disk before returning. */
    private void write(CommandEvent e, boolean durable) throws IOException {
        Path seg = segment(e.group(), e.edge());
        Files.createDirectories(seg.getParent());
        String prev = tailHash(e.group(), e.edge());
        String hash = CommandChain.entryHash(e, prev);
        CommandLedgerEntry entry = new CommandLedgerEntry(e, prev, hash);
        byte[] line = (mapper.writeValueAsString(entry) + "\n").getBytes(StandardCharsets.UTF_8);
        if (!durable) {
            Files.write(seg, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            return;
        }
        try (FileChannel ch = FileChannel.open(seg, StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                StandardOpenOption.APPEND)) {
            ByteBuffer buf = ByteBuffer.wrap(line);
            while (buf.hasRemaining()) {
                ch.write(buf);
            }
            ch.force(true);
        }
    }

    /**
     * The hash this edge's chain currently ends with: the current segment's last entry, or the most
     * recent earlier segment's last entry when today's file does not exist yet, or GENESIS when
     * there is no history at all.
     */
    public synchronized String tailHash(String group, String edge) throws IOException {
        Path seg = segment(group, edge);
        if (Files.isRegularFile(seg)) {
            List<CommandLedgerEntry> entries = read(seg);
            if (!entries.isEmpty()) {
                return entries.get(entries.size() - 1).entryHash();
            }
        }
        Path dir = seg.getParent();
        if (dir == null || !Files.isDirectory(dir)) {
            return CommandChain.GENESIS;
        }
        // The previous segment by name; the day format sorts lexicographically.
        try (var stream = Files.list(dir)) {
            Path prevSeg = stream.filter(p -> p.getFileName().toString().endsWith(".jsonl"))
                    .filter(p -> p.getFileName().toString().compareTo(seg.getFileName().toString()) < 0)
                    .max(Path::compareTo).orElse(null);
            if (prevSeg == null) {
                return CommandChain.GENESIS;
            }
            List<CommandLedgerEntry> prev = read(prevSeg);
            return prev.isEmpty() ? CommandChain.GENESIS : prev.get(prev.size() - 1).entryHash();
        }
    }

    public List<CommandLedgerEntry> readCurrent(String group, String edge) throws IOException {
        return read(segment(group, edge));
    }

    /** Verify today's segment against the predecessor it should link to. */
    public CommandChainVerdict verifyCurrent(String group, String edge, String expectedPrev) throws IOException {
        Path seg = segment(group, edge);
        List<String> lines = Files.isRegularFile(seg) ? Files.readAllLines(seg, StandardCharsets.UTF_8) : List.of();
        List<CommandLedgerEntry> entries = new ArrayList<>();
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isBlank()) {
                continue;
            }
            try {
                entries.add(mapper.readValue(line, CommandLedgerEntry.class));
            } catch (Exception malformed) {
                // A finding, not a crash: two unsynchronized appends can interleave into a line no
                // parser will accept, and a verifier that throws reports a crash where it should
                // report the break it just found.
                return CommandChainVerdict.unparseable(i);
            }
        }
        return CommandChain.verify(entries, expectedPrev);
    }

    private List<CommandLedgerEntry> read(Path seg) throws IOException {
        if (!Files.isRegularFile(seg)) {
            return List.of();
        }
        List<CommandLedgerEntry> out = new ArrayList<>();
        for (String line : Files.readAllLines(seg, StandardCharsets.UTF_8)) {
            if (line.isBlank()) {
                continue;
            }
            try {
                out.add(mapper.readValue(line, CommandLedgerEntry.class));
            } catch (Exception malformed) {
                // readCurrent is a convenience for callers that already verified; verifyCurrent is
                // the one that reports. Stop rather than silently skipping a line.
                break;
            }
        }
        return out;
    }

    private static String safe(String s) {
        return s == null ? "_" : s.replaceAll("[^A-Za-z0-9_.-]", "-");
    }
}
