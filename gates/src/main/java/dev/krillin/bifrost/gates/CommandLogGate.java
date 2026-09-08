package dev.krillin.bifrost.gates;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;

import dev.krillin.bifrost.core.command.CommandChain;
import dev.krillin.bifrost.core.command.CommandChainVerdict;
import dev.krillin.bifrost.core.command.CommandLedgerEntry;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;

/**
 * Read the command ledger back. A record nobody can verify from outside the process that wrote it is
 * a write-only file, so this is the other half of R2 rather than a convenience.
 *
 * <pre>
 *   command-log verify &lt;segment.jsonl&gt; [--expect-prev &lt;hash&gt;]
 *   command-log tail   &lt;segment.jsonl&gt; [n]
 * </pre>
 *
 * <p>{@code --expect-prev} is what lets an archived segment be checked on its own: segments link by
 * their predecessor's tail hash rather than each restarting at genesis, so verifying one in
 * isolation means saying what it should link to. Without the flag, genesis is assumed — correct only
 * for the very first segment.
 *
 * <p>Exit codes follow {@code activation verify-chain}: <b>0</b> intact, <b>1</b> broken (with the
 * index and rule), <b>2</b> usage or no such segment. The third is not pedantry — the R2 gate
 * deliberately makes a path unwritable, and "the chain is broken" and "you pointed at nothing" are
 * different findings.
 *
 * <p><b>What a passing verify does and does not mean.</b> It means no entry was edited, deleted from
 * the middle, or reordered. It does <b>not</b> mean the file is complete: truncation leaves every
 * check satisfied. See {@link CommandChain}.
 */
public final class CommandLogGate {

    public static int run(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: gates command-log <verify|tail> <segment.jsonl> [--expect-prev <hash> | n]");
            return 2;
        }
        String sub = args[0];
        Path seg = Path.of(args[1]);
        if (!Files.isRegularFile(seg)) {
            System.err.println("[COMMAND-LOG] no such segment: " + seg);
            return 2;
        }
        try {
            return switch (sub) {
                case "verify" -> verify(seg, expectPrev(args));
                case "tail" -> tail(seg, args.length > 2 ? Integer.parseInt(args[2]) : 20);
                default -> {
                    System.err.println("[COMMAND-LOG] unknown subcommand: " + sub);
                    yield 2;
                }
            };
        } catch (Exception e) {
            System.err.println("[COMMAND-LOG] ERROR: " + e.getMessage());
            return 2;
        }
    }

    private static String expectPrev(String[] args) {
        for (int i = 2; i < args.length - 1; i++) {
            if ("--expect-prev".equals(args[i])) {
                return args[i + 1];
            }
        }
        return CommandChain.GENESIS;
    }

    private static int verify(Path seg, String expectedPrev) throws Exception {
        ObjectMapper mapper = JsonMapperFactory.create();
        List<String> lines = Files.readAllLines(seg, StandardCharsets.UTF_8);
        List<CommandLedgerEntry> entries = new ArrayList<>();
        for (int i = 0; i < lines.size(); i++) {
            if (lines.get(i).isBlank()) {
                continue;
            }
            try {
                entries.add(mapper.readValue(lines.get(i), CommandLedgerEntry.class));
            } catch (Exception malformed) {
                System.out.println("[COMMAND-LOG] BROKEN at " + i + ": command.chain.unparseable-line");
                return 1;
            }
        }
        CommandChainVerdict v = CommandChain.verify(entries, expectedPrev);
        if (v.intact()) {
            System.out.println("[COMMAND-LOG] INTACT " + entries.size() + " entries in " + seg.getFileName());
            return 0;
        }
        System.out.println("[COMMAND-LOG] BROKEN at " + v.brokenIndex() + ": " + v.rule());
        return 1;
    }

    private static int tail(Path seg, int n) throws Exception {
        ObjectMapper mapper = JsonMapperFactory.create();
        List<String> lines = Files.readAllLines(seg, StandardCharsets.UTF_8).stream()
                .filter(l -> !l.isBlank()).toList();
        for (String line : lines.subList(Math.max(0, lines.size() - n), lines.size())) {
            CommandLedgerEntry e = mapper.readValue(line, CommandLedgerEntry.class);
            System.out.println(e.event().at() + "  " + e.event().phase() + "/" + e.event().outcome()
                    + "  sub=" + e.event().subject() + "  cmd=" + e.event().command()
                    + "  val=" + e.event().value()
                    + (e.event().reason() == null ? "" : "  reason=" + e.event().reason()));
        }
        return 0;
    }

    public static void main(String[] args) {
        System.exit(run(args));
    }

    private CommandLogGate() {
    }
}
