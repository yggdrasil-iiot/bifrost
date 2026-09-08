package dev.krillin.bifrost.core.command;

/**
 * The persisted unit: one {@link CommandEvent} plus its chain links, serialized as a JSONL line.
 *
 * <p>{@code prevHash} is the prior entry's {@code entryHash} — or, for a segment's first entry, the
 * PREVIOUS SEGMENT's tail hash. Only the very first segment starts at {@link CommandChain#GENESIS}.
 * Restarting each segment at genesis would let any segment, including the current one, be deleted or
 * rewritten with nothing to contradict it.
 */
public record CommandLedgerEntry(CommandEvent event, String prevHash, String entryHash) {
}
